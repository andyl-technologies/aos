//! Dedicated protected-journal adapter for portable runtime execution records.
//!
//! ```text
//! authority = AOSRAA01 || currentness_and_probe[32] || ledger[32]
//! output-v2 = AOSROV02 || store_binding[32]
//! output-marker = AOSEOM01 || assignment[32] || parent_output_bytes:u64be
//! output-claim = 'o' || execution[16] => AOSEOR02 accepted-Create claim
//! sequence  = operation_sequence:u64be || operation[16] || issue_anchor[32]
//! resource  = prior_ledger[32] || output_reservation[32]
//!             || successor_ledger[32] || admission[32]
//!             || global_capacity_reservation[32]
//! terminal  = admission[32] || operation[16] || terminal_effect[32]
//!             || global_capacity_reservation[32]
//! route     = 'q' || operation[16] => AOSHRQ01 protected agent request
//! outcome   = 'u' || operation[16] => AOSHRO01 signed outcome custody
//! ```

use std::collections::{BTreeMap, BTreeSet};

use aos_sandbox_agent::SignedAgentOutcomePacketV1;
use aos_sandbox_core::runtime_backend::{
    AdmissionCommitDispositionV1, AdmissionCommitError, AdmissionCurrentnessV1,
    AdmissionStoreCommitV1, AdmittedExecutionV1, DurableAdmissionCommitV1,
    DurableExecutionEffectV1, EffectCommitDispositionV1, EffectCommitError, EffectCompletionV1,
    EffectPhaseV1, EffectStoreCommitV1, EffectStoreTransitionV1, ExecutionAdmissionDraftV1,
    ExecutionAdmissionStore, ExecutionEffectStore, RuntimeModelError,
    decode_durable_execution_admission_v1, decode_durable_execution_effect_v1,
    encode_durable_execution_admission_v1, encode_durable_execution_effect_v1,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest, ObservationSequence, OperationId};
use sha2::{Digest as _, Sha256};

use crate::execution_output_reservation::{
    CLAIM_KEY_PREFIX, ClaimDraft, ExecutionOutputReservationCommitV1,
    ExecutionOutputReservationErrorV1, ExecutionOutputReservationRecoveryResultV1,
    ExecutionOutputReservationRecoveryV1, MARKER_KEY as OUTPUT_MARKER_KEY, RetainedClaim,
    accepted_claim, admit_next, claim_key, decode_claim, marker_bytes, replay_ledger,
};
use crate::execution_parent_resource::ExecutionParentResourceSourceV1;
use crate::journal::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1,
    GlobalCapacityReservationV1, Journal, JournalError, JournalRecord, JournalTransaction,
    ProtectedJournalAuthority, ProtectedJournalSnapshot, RecordNamespace,
};

use super::argument_observation::{ArgumentObservationRecordV1, KEY_PREFIX as ARGUMENT_KEY_PREFIX};
use super::evidence::{
    JournalExecutionCompletionV1, completion_observes_terminal_execution, validate_completion,
};
use super::host_output_source::VerifiedHostOutputReserveSourceV1;
use super::outcome_record::HostAgentOutcomeRecordV1;
use super::route_record::{
    ProtectedAgentRoutePeerV1, ProtectedAgentRouteRecordV1, ROUTE_KEY_PREFIX, route_key,
};

mod output_budget;
mod output_correlation;

use output_budget::{OutputBudget, decode_output_claim, reserve_output_bytes};
use output_correlation::{
    HostOutputCorrelationV1, KEY_PREFIX as HOST_OUTPUT_KEY_PREFIX, host_output_key,
};

const ADMISSION_KEY_PREFIX: u8 = b'a';
const ADMISSION_IDEMPOTENCY_KEY_PREFIX: u8 = b'i';
const ADMISSION_RESOURCE_KEY_PREFIX: u8 = b'r';
const EFFECT_KEY_PREFIX: u8 = b'e';
const SEQUENCE_KEY_PREFIX: u8 = b's';
const TERMINAL_KEY_PREFIX: u8 = b't';
const AGENT_OUTCOME_KEY_PREFIX: u8 = b'u';
const STORE_MARKER_KEY: &[u8] = b"runtime-execution-owner-v1";
const ADMISSION_AUTHORITY_KEY: &[u8] = b"runtime-execution-admission-authority-v1";
const ADMISSION_AUTHORITY_MAGIC: &[u8; 8] = b"AOSRAA01";
const OUTPUT_FORMAT_KEY: &[u8] = b"runtime-execution-output-v2";
const OUTPUT_FORMAT_MAGIC: &[u8; 8] = b"AOSROV02";
const TERMINAL_CAPACITY_RECORDS: u32 = 3;
const TERMINAL_CAPACITY_BYTES: u64 = 16 * 1_048_576;
const MAXIMUM_RUNTIME_EXECUTION_RECORDS: usize = 262_144;

/// Authenticated readback of the exact Host AOSEOR02/AOSHOP01 atomic append.
///
/// This proves provisional budget custody only. It does not establish physical
/// capture backing or authorize an execution effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtectedHostOutputReservationV1 {
    execution: ExecutionId,
    create_operation: OperationId,
    preissue_digest: ObjectDigest,
    claim_digest: ObjectDigest,
    carrier_digest: ObjectDigest,
    original_request_id: [u8; 16],
    assignment_digest: ObjectDigest,
    host_boot_id: [u8; 16],
    plan_digest: ObjectDigest,
    semantic_request_digest: ObjectDigest,
    correlation_digest: ObjectDigest,
    original_journal_sequence: u64,
}

impl ProtectedHostOutputReservationV1 {
    /// Returns the accepted execution named by the protected claim.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        self.execution
    }

    /// Returns the exact accepted Create operation.
    #[must_use]
    pub const fn create_operation(self) -> OperationId {
        self.create_operation
    }

    /// Returns the Controller protected preissue record digest.
    #[must_use]
    pub const fn preissue_digest(self) -> ObjectDigest {
        self.preissue_digest
    }

    /// Returns the raw AOSEOR02 claim digest.
    #[must_use]
    pub const fn claim_digest(self) -> ObjectDigest {
        self.claim_digest
    }

    /// Returns the signed AOSCIR01 carrier digest.
    #[must_use]
    pub const fn carrier_digest(self) -> ObjectDigest {
        self.carrier_digest
    }

    /// Returns the original authenticated reserve request identifier.
    #[must_use]
    pub const fn original_request_id(self) -> [u8; 16] {
        self.original_request_id
    }

    /// Returns the current assignment digest pinned by the reservation.
    #[must_use]
    pub const fn assignment_digest(self) -> ObjectDigest {
        self.assignment_digest
    }

    /// Returns the Host kernel boot identity pinned by the reservation.
    #[must_use]
    pub const fn host_boot_id(self) -> [u8; 16] {
        self.host_boot_id
    }

    /// Returns the verified signed broker-plan digest.
    #[must_use]
    pub const fn plan_digest(self) -> ObjectDigest {
        self.plan_digest
    }

    /// Returns the matched reserve-request semantic digest.
    #[must_use]
    pub const fn semantic_request_digest(self) -> ObjectDigest {
        self.semantic_request_digest
    }

    /// Returns the protected AOSHOP01 record digest.
    #[must_use]
    pub const fn correlation_digest(self) -> ObjectDigest {
        self.correlation_digest
    }

    /// Returns the original atomic append's protected journal sequence.
    #[must_use]
    pub const fn original_journal_sequence(self) -> u64 {
        self.original_journal_sequence
    }
}

/// Configures the initial protected assignment, probe, and resource ledger.
///
/// The value is configuration input, not admission authority. Authority exists
/// only after these bindings have been committed to the dedicated journal and
/// reloaded by [`JournalRuntimeExecutionStoreV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProtectedExecutionAdmissionStateV1 {
    authority_binding: ObjectDigest,
    resource_ledger: ObjectDigest,
}

impl ProtectedExecutionAdmissionStateV1 {
    /// Derives initial protected admission state from typed currentness.
    ///
    #[must_use]
    pub(crate) fn new(currentness: &AdmissionCurrentnessV1) -> Self {
        Self {
            authority_binding: admission_authority_binding(currentness),
            resource_ledger: currentness.resource_ledger(),
        }
    }

    /// Returns the current protected resource-ledger head.
    #[must_use]
    pub const fn resource_ledger(&self) -> ObjectDigest {
        self.resource_ledger
    }

    /// Returns the fixed authority binding retained by the admission ledger.
    #[must_use]
    pub const fn authority_binding(&self) -> ObjectDigest {
        self.authority_binding
    }
}

/// Opaque authority for resolving one ambiguous protected-journal commit.
///
/// The token has no public constructor and is bound to the exact configured
/// store, record key, transaction identity, predecessor, successor, and any
/// admission capacity reservation.
#[must_use = "ambiguous execution durability must be resolved after protected reopen"]
pub struct ExecutionJournalRecoveryTokenV1 {
    store_binding: ObjectDigest,
    kind: RecoveryKind,
    key: Vec<u8>,
    transaction: [u8; 16],
    expected_record: ObjectDigest,
    prior_record: Option<ObjectDigest>,
    capacity_reservation: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryKind {
    Admission,
    Effect,
}

/// Authenticates one durable effect under an exact protected journal snapshot.
#[must_use = "authenticated recovery evidence must be reconciled or retained"]
pub struct AuthenticatedJournalExecutionRecoveryV1 {
    effect: DurableExecutionEffectV1,
    journal_head: ObjectDigest,
    record_provenance: ObjectDigest,
}

impl AuthenticatedJournalExecutionRecoveryV1 {
    /// Borrows the exact authenticated durable effect.
    #[must_use]
    pub const fn effect(&self) -> &DurableExecutionEffectV1 {
        &self.effect
    }

    /// Returns the authenticated protected journal-head commitment.
    #[must_use]
    pub const fn journal_head(&self) -> ObjectDigest {
        self.journal_head
    }

    /// Returns the authenticated protected record provenance.
    #[must_use]
    pub const fn record_provenance(&self) -> ObjectDigest {
        self.record_provenance
    }
}

/// Reserves one live-process, one-shot crossing of the backend effect boundary.
#[must_use = "dropping a dispatch permit leaves the Issued effect recoverable, not retryable"]
pub(crate) struct PreparedExecutionDispatchV1 {
    effect: DurableExecutionEffectV1,
    snapshot: ProtectedJournalSnapshot,
    store_binding: ObjectDigest,
}

/// Owns a dedicated protected execution journal and its live dispatch fence.
pub(crate) struct JournalRuntimeExecutionStoreV1<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
    store_binding: ObjectDigest,
    agent_peer: ProtectedAgentRoutePeerV1,
    freshly_issued: BTreeSet<[u8; 16]>,
    live_dispatches: BTreeSet<[u8; 16]>,
    authorized_completions: BTreeSet<ObjectDigest>,
}

impl<'journal> JournalRuntimeExecutionStoreV1<'journal> {
    /// Initializes and claims an empty dedicated protected execution journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] if the journal is nonempty,
    /// unprotected, the binding is zero, or initialization durability fails.
    pub(crate) fn initialize(
        journal: &'journal mut Journal,
        store_binding: ObjectDigest,
        admission_state: ProtectedExecutionAdmissionStateV1,
        agent_peer: ProtectedAgentRoutePeerV1,
    ) -> Result<Self, JournalRuntimeExecutionError> {
        if store_binding.as_bytes() == &[0; 32] {
            return Err(JournalRuntimeExecutionError::InvalidBinding);
        }
        let mut authority = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RuntimeExecution,
        )?;
        if !authority.is_materialized_empty()? {
            return Err(JournalRuntimeExecutionError::AlreadyInitialized);
        }
        let transaction = transaction_id(b"store-owner", store_binding);
        let transaction_record = JournalTransaction::new(
            transaction,
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    STORE_MARKER_KEY.to_vec(),
                    store_binding.as_bytes().to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    ADMISSION_AUTHORITY_KEY.to_vec(),
                    encode_admission_authority(&admission_state),
                ),
            ],
        )?;
        let preflight =
            authority.preflight_transactions(std::slice::from_ref(&transaction_record))?;
        authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction_record))?;
        authority.commit(&transaction_record)?;
        Ok(Self {
            authority,
            store_binding,
            agent_peer,
            freshly_issued: BTreeSet::new(),
            live_dispatches: BTreeSet::new(),
            authorized_completions: BTreeSet::new(),
        })
    }

    /// Claims a dedicated protected `Effect`-namespace journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] when the journal is not a
    /// healthy protected single-namespace store or `store_binding` is zero.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        store_binding: ObjectDigest,
        agent_peer: ProtectedAgentRoutePeerV1,
    ) -> Result<Self, JournalRuntimeExecutionError> {
        if store_binding.as_bytes() == &[0; 32] {
            return Err(JournalRuntimeExecutionError::InvalidBinding);
        }
        let authority = journal.claim_global_capacity_reservation_authority(
            GlobalCapacityReservationPurposeV1::RuntimeExecution,
        )?;
        validate_runtime_execution_replay(&authority, store_binding, agent_peer)?;
        Ok(Self {
            authority,
            store_binding,
            agent_peer,
            freshly_issued: BTreeSet::new(),
            live_dispatches: BTreeSet::new(),
            authorized_completions: BTreeSet::new(),
        })
    }

    /// Loads current protected admission ledger and capacity state.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] when the dedicated authority
    /// record is absent, malformed, or unavailable.
    pub fn load_admission_state(
        &self,
    ) -> Result<ProtectedExecutionAdmissionStateV1, JournalRuntimeExecutionError> {
        let bytes = self
            .authority
            .get(ADMISSION_AUTHORITY_KEY)?
            .ok_or(JournalRuntimeExecutionError::UninitializedStore)?;
        decode_admission_authority(bytes)
    }

    /// Reads one provisional v2 claim from this cold-validated protected store.
    ///
    /// Absence is not admission authority, and the returned claim does not
    /// establish current Host or physical capture-storage state.
    ///
    /// # Errors
    ///
    /// Returns an error if the v2 format binding or retained claim is corrupt.
    pub(crate) fn load_accepted_output_v2(
        &self,
        execution: ExecutionId,
    ) -> Result<Option<RetainedClaim>, JournalRuntimeExecutionError> {
        match self.authority.get(OUTPUT_FORMAT_KEY)? {
            None => return Ok(None),
            Some(bytes) if bytes == output_format_bytes(self.store_binding) => {}
            Some(_) => return Err(JournalRuntimeExecutionError::CorruptRecord),
        }
        let Some(bytes) = self.authority.get(&claim_key(execution))? else {
            return Ok(None);
        };
        let claim = decode_claim(bytes)?;
        if claim.execution != *execution.as_bytes() {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(Some(claim))
    }

    pub(crate) fn load_argument_observation_v1(
        &self,
        execution: ExecutionId,
    ) -> Result<Option<ArgumentObservationRecordV1>, JournalRuntimeExecutionError> {
        self.authority
            .get(&ArgumentObservationRecordV1::key(execution))?
            .map(ArgumentObservationRecordV1::decode)
            .transpose()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
    }

    pub(crate) fn begin_argument_observation_v1(
        &mut self,
        proposed: ArgumentObservationRecordV1,
    ) -> Result<ArgumentObservationRecordV1, JournalRuntimeExecutionError> {
        let retained = self
            .load_accepted_output_v2(proposed.execution)?
            .ok_or(JournalRuntimeExecutionError::RecordConflict)?;
        if retained.create_operation != *proposed.create_operation.as_bytes()
            || retained.assignment != proposed.request.runtime().assignment_digest()
            || retained.stream_limits.is_none()
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        // A previously issued challenge cannot mint fresh-looking evidence
        // after a Host process restart, even if its old handshake is replayed.
        if self
            .load_argument_observation_v1(proposed.execution)?
            .is_some()
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        let value = proposed
            .encode()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        let transaction = JournalTransaction::new(
            transaction_id(
                b"argument-observation-begin",
                proposed
                    .digest()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            ),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                ArgumentObservationRecordV1::key(proposed.execution).to_vec(),
                value,
            )],
        )?;
        self.authority
            .commit(&transaction)
            .map_err(|_| JournalRuntimeExecutionError::ObservationOutcomeUnknown)?;
        Ok(proposed)
    }

    pub(crate) fn complete_argument_observation_v1(
        &mut self,
        execution: ExecutionId,
        create_operation: OperationId,
        request: &aos_sandbox_agent::GuestRuntimeArgumentObserveRequestV1,
        packet_digest: ObjectDigest,
    ) -> Result<ObjectDigest, JournalRuntimeExecutionError> {
        let mut record = self
            .load_argument_observation_v1(execution)?
            .ok_or(JournalRuntimeExecutionError::RecordConflict)?;
        if record.create_operation != create_operation
            || &record.request != request
            || packet_digest.as_bytes() == &[0; 32]
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        if let Some(prior) = record.signed_packet_digest {
            return if prior == packet_digest {
                record
                    .digest()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
            } else {
                Err(JournalRuntimeExecutionError::RecordConflict)
            };
        }
        record.signed_packet_digest = Some(packet_digest);
        let value = record
            .encode()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        let transaction = JournalTransaction::new(
            transaction_id(
                b"argument-observation-complete",
                record
                    .digest()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            ),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                ArgumentObservationRecordV1::key(execution).to_vec(),
                value,
            )],
        )?;
        self.authority
            .commit(&transaction)
            .map_err(|_| JournalRuntimeExecutionError::ObservationOutcomeUnknown)?;
        record
            .digest()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
    }

    /// Commits an accepted Create output claim into this execution store.
    ///
    /// The v2 marker and first zero- or nonzero-byte claim commit atomically.
    /// An existing v1 store with admissions cannot switch formats in place.
    /// This provisional claim is not physical capture-storage or Host authority.
    ///
    /// # Errors
    ///
    /// Returns an error for stale accepted input, a legacy admission, capacity
    /// exhaustion, conflicting claims, or corrupt protected replay.
    pub(crate) fn reserve_accepted_output_v2(
        &mut self,
        controller: &mut Journal,
        create_operation: OperationId,
        execution: ExecutionId,
        parent: &ExecutionParentResourceSourceV1,
    ) -> Result<ExecutionOutputReservationCommitV1, JournalRuntimeExecutionError> {
        let draft = accepted_claim(controller, create_operation, execution, parent)?;
        self.reserve_claim_draft_v2(draft)
    }

    // Future Host grant verification must produce the exact draft before
    // entering this protected ledger. This function never trusts source data.
    fn reserve_claim_draft_v2(
        &mut self,
        draft: ClaimDraft,
    ) -> Result<ExecutionOutputReservationCommitV1, JournalRuntimeExecutionError> {
        let execution = draft.record.execution();
        let format = output_format_bytes(self.store_binding);
        let format_seen = match self.authority.get(OUTPUT_FORMAT_KEY)? {
            Some(bytes) if bytes == format => true,
            Some(_) => return Err(JournalRuntimeExecutionError::CorruptRecord),
            None => false,
        };
        if !format_seen
            && self
                .authority
                .records()?
                .any(|(key, _)| matches!(key, [ADMISSION_KEY_PREFIX, ..] if key.len() == 17))
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        let key = claim_key(execution);
        let readback = replay_ledger(
            self.authority
                .records()?
                .filter(|(key, _)| output_record_key(key)),
            draft.assignment,
            draft.parent_bytes,
            &key,
            &draft.bytes,
        )?;
        if format_seen != readback.marker_seen {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        if readback.replay {
            return Ok(ExecutionOutputReservationCommitV1::Committed(draft.record));
        }
        admit_next(readback.used, draft.requested_bytes, draft.parent_bytes)?;

        let mut writes = Vec::with_capacity(if format_seen { 1 } else { 3 });
        if !format_seen {
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                OUTPUT_FORMAT_KEY.to_vec(),
                format.to_vec(),
            ));
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                OUTPUT_MARKER_KEY.to_vec(),
                marker_bytes(draft.assignment, draft.parent_bytes).to_vec(),
            ));
        }
        writes.push(JournalRecord::put(
            RecordNamespace::Effect,
            key,
            draft.bytes.to_vec(),
        ));
        let transaction = JournalTransaction::new(*execution.as_bytes(), writes)?;
        match self.authority.commit(&transaction) {
            Ok(_) => Ok(ExecutionOutputReservationCommitV1::Committed(draft.record)),
            Err(_) => Ok(ExecutionOutputReservationCommitV1::RecoveryRequired(
                ExecutionOutputReservationRecoveryV1 {
                    store_binding: self.store_binding,
                    expected: draft.record,
                    expected_bytes: draft.bytes,
                },
            )),
        }
    }

    /// Appends one signed-source AOSEOR02 claim and its Host attempt correlation.
    ///
    /// The caller must first durably admit the matching Host broker effect.
    /// Failure after the append is outcome-unknown: only cold protected query
    /// may resolve it, and no new request ID may be generated for a retry.
    ///
    /// # Errors
    ///
    /// Rejects conflicting or corrupt protected custody, insufficient output
    /// capacity, or an ambiguous journal commit.
    pub(crate) fn reserve_host_output_v1(
        &mut self,
        verified: &VerifiedHostOutputReserveSourceV1,
    ) -> Result<ProtectedHostOutputReservationV1, JournalRuntimeExecutionError> {
        let source = verified.source();
        let claim_bytes = source.canonical_output_claim();
        let claim = decode_claim(claim_bytes)?;
        let execution = source.preissue().execution();
        let key = claim_key(execution);
        let correlation_key = host_output_key(execution);

        if let Some(existing) = self.authority.get(&correlation_key)? {
            let correlation = HostOutputCorrelationV1::decode(existing)
                .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
            if self.authority.get(&key)? != Some(claim_bytes.as_slice())
                || correlation.execution != execution
                || correlation.create_operation != source.preissue().create_operation()
                || correlation.original_request_id != verified.original_request_id()
                || correlation.preissue_digest != source.preissue().record_digest()
                || correlation.claim_digest != source.output_claim_digest()
                || correlation.carrier_digest != source.carrier_digest()
                || correlation.plan_digest != verified.plan_digest()
                || correlation.semantic_request_digest != verified.semantic_request_digest()
                || correlation.assignment_digest != verified.assignment_digest()
                || correlation.host_boot_id != verified.host_boot_id()
                || correlation.deadline_boottime_nanoseconds
                    != source.preissue().deadline_boottime_nanoseconds()
                || correlation.original_journal_sequence > self.authority.snapshot()?.sequence()
            {
                return Err(JournalRuntimeExecutionError::RecordConflict);
            }
            return host_output_receipt(correlation);
        }
        if self.authority.get(&key)?.is_some() {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        let format = output_format_bytes(self.store_binding);
        let format_seen = match self.authority.get(OUTPUT_FORMAT_KEY)? {
            Some(bytes) if bytes == format => true,
            Some(_) => return Err(JournalRuntimeExecutionError::CorruptRecord),
            None => false,
        };
        if !format_seen
            && self.authority.records()?.any(|(record_key, _)| {
                matches!(record_key, [ADMISSION_KEY_PREFIX, ..] if record_key.len() == 17)
            })
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        let readback = replay_ledger(
            self.authority
                .records()?
                .filter(|(record_key, _)| output_record_key(record_key)),
            claim.assignment,
            claim.parent_bytes,
            &key,
            claim_bytes,
        )?;
        if format_seen != readback.marker_seen || readback.replay {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        admit_next(readback.used, claim.requested_bytes, claim.parent_bytes)?;

        let write_count = if format_seen { 2 } else { 4 };
        let next_sequence =
            predicted_commit_sequence(self.authority.snapshot()?.sequence(), write_count)?;
        let correlation = HostOutputCorrelationV1 {
            execution,
            create_operation: source.preissue().create_operation(),
            preissue_digest: source.preissue().record_digest(),
            claim_digest: source.output_claim_digest(),
            carrier_digest: source.carrier_digest(),
            original_request_id: verified.original_request_id(),
            assignment_digest: verified.assignment_digest(),
            host_boot_id: verified.host_boot_id(),
            plan_digest: verified.plan_digest(),
            semantic_request_digest: verified.semantic_request_digest(),
            deadline_boottime_nanoseconds: source.preissue().deadline_boottime_nanoseconds(),
            original_journal_sequence: next_sequence,
        };
        let correlation_bytes = correlation
            .encode()
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let mut writes = Vec::with_capacity(write_count);
        if !format_seen {
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                OUTPUT_FORMAT_KEY.to_vec(),
                format.to_vec(),
            ));
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                OUTPUT_MARKER_KEY.to_vec(),
                marker_bytes(claim.assignment, claim.parent_bytes).to_vec(),
            ));
        }
        writes.push(JournalRecord::put(
            RecordNamespace::Effect,
            key,
            claim_bytes.to_vec(),
        ));
        writes.push(JournalRecord::put(
            RecordNamespace::Effect,
            correlation_key,
            correlation_bytes.to_vec(),
        ));

        let transaction = JournalTransaction::new(
            transaction_id(b"host-output", source.carrier_digest()),
            writes,
        )?;
        self.authority
            .commit(&transaction)
            .map_err(|_| JournalRuntimeExecutionError::ObservationOutcomeUnknown)?;
        let committed_sequence = self
            .authority
            .snapshot()
            .map_err(|_| JournalRuntimeExecutionError::ObservationOutcomeUnknown)?
            .sequence();
        if committed_sequence != next_sequence {
            return Err(JournalRuntimeExecutionError::ObservationOutcomeUnknown);
        }
        host_output_receipt(correlation)
            .map_err(|_| JournalRuntimeExecutionError::ObservationOutcomeUnknown)
    }

    /// Reads one prior exact Host reservation without appending a new claim.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched request/correlation or corrupt protected record.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn query_host_output_v1(
        &self,
        execution: ExecutionId,
        create_operation: OperationId,
        preissue_digest: ObjectDigest,
        claim_digest: ObjectDigest,
        carrier_digest: ObjectDigest,
        original_request_id: [u8; 16],
        assignment_digest: ObjectDigest,
        host_boot_id: [u8; 16],
    ) -> Result<Option<ProtectedHostOutputReservationV1>, JournalRuntimeExecutionError> {
        let correlation_key = host_output_key(execution);
        let Some(bytes) = self.authority.get(&correlation_key)? else {
            return match self.authority.get(&claim_key(execution))? {
                Some(_) => Err(JournalRuntimeExecutionError::RecordConflict),
                None => Ok(None),
            };
        };
        let correlation = HostOutputCorrelationV1::decode(bytes)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let claim = self
            .authority
            .get(&claim_key(execution))?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let retained = decode_claim(claim)?;
        if correlation.execution != execution
            || correlation.create_operation != create_operation
            || correlation.preissue_digest != preissue_digest
            || correlation.claim_digest != claim_digest
            || correlation.carrier_digest != carrier_digest
            || correlation.original_request_id != original_request_id
            || correlation.assignment_digest != assignment_digest
            || correlation.host_boot_id != host_boot_id
            || retained.create_operation != *correlation.create_operation.as_bytes()
            || retained.assignment != correlation.assignment_digest
            || ObjectDigest::from_bytes(Sha256::digest(claim).into()) != claim_digest
            || correlation.original_journal_sequence > self.authority.snapshot()?.sequence()
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        host_output_receipt(correlation).map(Some)
    }

    /// Resolves an ambiguous v2 claim after this store has cold-reopened.
    ///
    /// # Errors
    ///
    /// Returns an error if the protected store or retained claim is corrupt.
    pub(crate) fn recover_accepted_output_v2(
        &self,
        token: ExecutionOutputReservationRecoveryV1,
    ) -> Result<ExecutionOutputReservationRecoveryResultV1, JournalRuntimeExecutionError> {
        if token.store_binding != self.store_binding {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        let format_seen = match self.authority.get(OUTPUT_FORMAT_KEY)? {
            Some(bytes) if bytes == output_format_bytes(self.store_binding) => true,
            Some(_) => return Err(JournalRuntimeExecutionError::CorruptRecord),
            None => false,
        };
        let output = token.expected.output();
        let readback = replay_ledger(
            self.authority
                .records()?
                .filter(|(key, _)| output_record_key(key)),
            output.assignment_digest(),
            output
                .parent_reservations()
                .get(aos_sandbox_core::ResourceDimension::OutputBytes),
            &claim_key(token.expected.execution()),
            &token.expected_bytes,
        )?;
        if format_seen != readback.marker_seen {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        if !readback.replay {
            return Ok(ExecutionOutputReservationRecoveryResultV1::NotCommitted);
        }
        Ok(ExecutionOutputReservationRecoveryResultV1::Committed(
            token.expected,
        ))
    }

    /// Loads one exact admitted execution from protected current state.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] for unavailable protected
    /// authority or malformed durable bytes.
    pub fn load_admission(
        &self,
        execution: ExecutionId,
    ) -> Result<Option<AdmittedExecutionV1>, JournalRuntimeExecutionError> {
        let key = admission_key(execution);
        self.authority
            .get(&key)?
            .map(decode_durable_execution_admission_v1)
            .transpose()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
    }

    /// Loads one exact effect by its durable operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] for unavailable protected
    /// authority or malformed durable bytes.
    pub fn load_effect(
        &self,
        operation: &[u8; 16],
    ) -> Result<Option<DurableExecutionEffectV1>, JournalRuntimeExecutionError> {
        let key = effect_key(operation);
        self.authority
            .get(&key)?
            .map(decode_durable_execution_effect_v1)
            .transpose()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
    }

    /// Loads durable recovery evidence before any live backend inventory call.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] for absent/corrupt state or
    /// unavailable protected journal provenance.
    pub fn load_recovery(
        &self,
        operation: &[u8; 16],
    ) -> Result<AuthenticatedJournalExecutionRecoveryV1, JournalRuntimeExecutionError> {
        let snapshot = self.authority.snapshot()?;
        let effect = self
            .load_effect(operation)?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let admission = self
            .load_admission(effect.admission().execution())?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        if admission != *effect.admission() {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        let idempotency = self
            .authority
            .get(&admission_idempotency_key(
                admission.idempotency().operation().as_bytes(),
            ))?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let resource = self
            .authority
            .get(&admission_resource_key(admission.execution()))?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let expected_resource = admission_resource_prefix_from_admission(&admission);
        if idempotency != admission.admission_commitment().as_bytes()
            || resource.len() != 160
            || resource.get(..128) != Some(expected_resource.as_slice())
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        let capacity_reservation: [u8; 32] = resource[128..160]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        if capacity_reservation == [0; 32] {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        let capacity_request = admitted_capacity_request(self.store_binding, &admission);
        let admission_transaction = transaction_id(b"admission", admission.admission_commitment());
        let settlement_is_proven = self.terminal_marker_proves_admission(&admission)?;
        match self
            .authority
            .lookup_global_capacity_reservation_v1(capacity_reservation)?
        {
            Some(reservation)
                if !settlement_is_proven
                    && reservation.matches_request(&capacity_request, admission_transaction) => {}
            None if settlement_is_proven => {}
            _ => return Err(JournalRuntimeExecutionError::RecordConflict),
        }
        let journal_head = snapshot_commitment(self.store_binding, snapshot.sequence());
        let record_provenance = record_provenance(
            self.store_binding,
            snapshot.sequence(),
            effect.record_commitment(),
        );
        Ok(AuthenticatedJournalExecutionRecoveryV1 {
            effect,
            journal_head,
            record_provenance,
        })
    }

    /// Reserves a single live-process dispatch from an exact Issued record.
    ///
    /// Exact durable replay is resolved before the in-memory one-shot fence.
    /// After process crash, an Issued record is recovery-only and a newly
    /// claimed store has no authority to call this method for historical work.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] unless current protected bytes
    /// exactly match `effect`, it is Issued, and no permit was
    /// previously minted by this store instance.
    pub(crate) fn prepare_dispatch(
        &mut self,
        effect: &DurableExecutionEffectV1,
    ) -> Result<PreparedExecutionDispatchV1, JournalRuntimeExecutionError> {
        if effect.phase() != EffectPhaseV1::Issued {
            return Err(JournalRuntimeExecutionError::WrongPhase);
        }
        let operation = *effect.issue().idempotency().operation().as_bytes();
        if !self.freshly_issued.remove(&operation) {
            return Err(JournalRuntimeExecutionError::RecoveryOnly);
        }
        let key = effect_key(&operation);
        let stored = self
            .authority
            .get(&key)?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let stored = decode_durable_execution_effect_v1(stored)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        if stored.record_commitment() != effect.record_commitment() {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        if !self.live_dispatches.insert(operation) {
            return Err(JournalRuntimeExecutionError::DispatchAlreadyConsumed);
        }
        let snapshot = self.authority.snapshot()?;
        Ok(PreparedExecutionDispatchV1 {
            effect: effect.clone(),
            snapshot,
            store_binding: self.store_binding,
        })
    }

    /// Commits one exact agent route before handing its request to a backend.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] when the permit belongs to
    /// another store, any journal mutation intervened, the effect changed, or
    /// the route could not be durably read back. A failed append is recovery-
    /// only even if the caller did not observe its commit.
    pub(crate) fn consume_dispatch(
        &mut self,
        permit: PreparedExecutionDispatchV1,
        route: ProtectedAgentRouteRecordV1,
    ) -> Result<(), JournalRuntimeExecutionError> {
        if permit.store_binding != self.store_binding {
            return Err(JournalRuntimeExecutionError::InvalidBinding);
        }
        self.authority
            .validate_snapshot_for_effect(&permit.snapshot)?;
        let operation_id = permit.effect.issue().idempotency().operation();
        let operation = operation_id.as_bytes();
        let stored = self
            .authority
            .get(&effect_key(operation))?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let stored = decode_durable_execution_effect_v1(stored)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        if stored.record_commitment() != permit.effect.record_commitment() {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        route.validate_effect(&stored, true)?;
        let key = route_key(operation);
        if self.authority.get(&key)?.is_some() {
            return Err(JournalRuntimeExecutionError::DispatchAlreadyConsumed);
        }
        let bytes = route.encode()?;
        let record_digest = ObjectDigest::from_bytes(Sha256::digest(&bytes).into());
        let transaction = JournalTransaction::new(
            transaction_id(b"agent-route", record_digest),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                key.clone(),
                bytes.clone(),
            )],
        )?;
        let preflight = self
            .authority
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        self.authority.commit(&transaction)?;
        if self.authority.get(&key)? != Some(bytes.as_slice()) {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(())
    }

    /// Loads the original protected route for cold inspection, never dispatch.
    pub(crate) fn load_agent_route(
        &self,
        operation: &[u8; 16],
    ) -> Result<Option<ProtectedAgentRouteRecordV1>, JournalRuntimeExecutionError> {
        let Some(bytes) = self.authority.get(&route_key(operation))? else {
            return Ok(None);
        };
        let route = ProtectedAgentRouteRecordV1::decode(bytes)?;
        let effect = self
            .load_effect(operation)?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if route.request().operation_id().as_bytes() != operation {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        route.validate_effect(&effect, false)?;
        route.validate_peer(self.agent_peer)?;
        Ok(Some(route))
    }

    /// Commits one authenticated agent outcome before Host observation escapes.
    ///
    /// A failed append is ambiguous. The caller must cold-reopen and inspect
    /// the exact operation, not accept another packet in the same process.
    pub(crate) fn commit_signed_agent_outcome_packet(
        &mut self,
        operation: &[u8; 16],
        packet: &SignedAgentOutcomePacketV1,
        observation_sequence: ObservationSequence,
        observation_commitment: ObjectDigest,
    ) -> Result<(), JournalRuntimeExecutionError> {
        let route = self
            .load_agent_route(operation)?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        route.validate_signed_outcome(packet, self.agent_peer)?;
        let record = HostAgentOutcomeRecordV1::new(
            SignedAgentOutcomePacketV1::new(packet.outcome().clone(), *packet.signature())
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
            observation_sequence,
            observation_commitment,
        )?;
        let bytes = record.encode()?;
        let key = agent_outcome_key(operation);
        if let Some(previous) = self.authority.get(&key)? {
            return if previous == bytes {
                Ok(())
            } else {
                Err(JournalRuntimeExecutionError::RecordConflict)
            };
        }
        if self.committed_agent_outcome_at_observation_sequence(observation_sequence)? {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }

        let effect = self
            .load_effect(operation)?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if !matches!(
            effect.phase(),
            EffectPhaseV1::Issued | EffectPhaseV1::Indeterminate
        ) {
            return Err(JournalRuntimeExecutionError::WrongPhase);
        }
        let digest = ObjectDigest::from_bytes(Sha256::digest(&bytes).into());
        let transaction = JournalTransaction::new(
            transaction_id(b"agent-outcome", digest),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                key.clone(),
                bytes.clone(),
            )],
        )?;
        let preflight = self
            .authority
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        self.authority.commit(&transaction)?;
        if self.authority.get(&key)? != Some(bytes.as_slice()) {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(())
    }

    /// Checks whether durable guest custody already owns a Host sequence.
    pub(crate) fn committed_agent_outcome_at_observation_sequence(
        &self,
        sequence: ObservationSequence,
    ) -> Result<bool, JournalRuntimeExecutionError> {
        for (key, bytes) in self.authority.records()? {
            if key.first() != Some(&AGENT_OUTCOME_KEY_PREFIX) || key.len() != 17 {
                continue;
            }
            if HostAgentOutcomeRecordV1::decode(bytes)?.observation_sequence() == sequence {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Reports whether an earlier protected agent route still owns an effect.
    pub(crate) fn has_unsettled_agent_route(&self) -> Result<bool, JournalRuntimeExecutionError> {
        for (key, _) in self.authority.records()? {
            if key.first() != Some(&ROUTE_KEY_PREFIX) || key.len() != 17 {
                continue;
            }
            let operation: &[u8; 16] = key[1..]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
            let effect = self
                .load_effect(operation)?
                .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
            if matches!(
                effect.phase(),
                EffectPhaseV1::Issued | EffectPhaseV1::Indeterminate
            ) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Reads one exact signed packet from protected Host custody after restart.
    pub(crate) fn load_signed_agent_outcome_packet(
        &self,
        operation: &[u8; 16],
    ) -> Result<Option<HostAgentOutcomeRecordV1>, JournalRuntimeExecutionError> {
        let Some(bytes) = self.authority.get(&agent_outcome_key(operation))? else {
            return Ok(None);
        };
        let record = HostAgentOutcomeRecordV1::decode(bytes)?;
        let route = self
            .load_agent_route(operation)?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        route.validate_signed_outcome(record.packet(), self.agent_peer)?;
        Ok(Some(record))
    }

    pub(crate) fn disarm_recovery_issue(&mut self, effect: &DurableExecutionEffectV1) {
        self.freshly_issued
            .remove(effect.issue().idempotency().operation().as_bytes());
    }

    /// Commits only completion evidence minted for the exact effect operation.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] for evidence substitution,
    /// durable phase conflict, ambiguity, or corrupt protected state.
    pub fn commit_verified_completion(
        &mut self,
        effect: &DurableExecutionEffectV1,
        evidence: &JournalExecutionCompletionV1,
    ) -> Result<
        aos_sandbox_core::runtime_backend::ExecutionEffectTransitionV1<
            ExecutionJournalRecoveryTokenV1,
        >,
        JournalRuntimeExecutionError,
    > {
        validate_completion(effect, evidence.completion())?;
        let authorization = completion_authorization(effect, evidence.completion());
        self.authorized_completions.insert(authorization);
        let transition =
            aos_sandbox_core::runtime_backend::complete_effect(self, effect, evidence.completion())
                .map_err(Into::into);
        self.authorized_completions.remove(&authorization);
        transition
    }

    /// Resolves one ambiguous completion commit from retained exact evidence.
    ///
    /// This never performs a backend or agent operation and never creates a
    /// second journal transaction.
    ///
    /// # Errors
    ///
    /// Returns [`JournalRuntimeExecutionError`] for a foreign token, evidence
    /// substitution, corrupt protected state, or receipt mismatch.
    pub fn recover_verified_completion(
        &mut self,
        effect: &DurableExecutionEffectV1,
        evidence: &JournalExecutionCompletionV1,
        token: ExecutionJournalRecoveryTokenV1,
    ) -> Result<
        aos_sandbox_core::runtime_backend::ExecutionEffectTransitionV1<
            ExecutionJournalRecoveryTokenV1,
        >,
        JournalRuntimeExecutionError,
    > {
        validate_completion(effect, evidence.completion())?;
        let authorization = completion_authorization(effect, evidence.completion());
        self.authorized_completions.insert(authorization);
        let transition = aos_sandbox_core::runtime_backend::recover_effect_completion(
            self,
            effect,
            evidence.completion(),
            token,
        )
        .map_err(Into::into);
        self.authorized_completions.remove(&authorization);
        transition
    }

    fn commit_admission(
        &mut self,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<ExecutionJournalRecoveryTokenV1>, AdmissionCommitError> {
        let admission_key = admission_key(draft.execution());
        let idempotency_key = admission_idempotency_key(draft.idempotency().operation().as_bytes());
        let resource_key = admission_resource_key(draft.execution());
        if let Some(replay) =
            self.admission_replay(draft, &admission_key, &idempotency_key, &resource_key)?
        {
            return Ok(AdmissionStoreCommitV1::Committed(replay));
        }

        let protected_state = self
            .authority
            .get(ADMISSION_AUTHORITY_KEY)
            .map_err(map_admission_journal_error)?
            .ok_or(AdmissionCommitError::StaleAuthority)
            .and_then(|bytes| {
                decode_admission_authority(bytes).map_err(|_| AdmissionCommitError::CorruptRecord)
            })?;
        if protected_state.authority_binding != admission_authority_binding(draft.currentness())
            || protected_state.resource_ledger != draft.currentness().resource_ledger()
        {
            return Err(AdmissionCommitError::StaleAuthority);
        }
        reserve_output_bytes(&self.authority, draft)?;
        let advanced_ledger = advance_resource_ledger(draft);
        let advanced_state = ProtectedExecutionAdmissionStateV1 {
            authority_binding: protected_state.authority_binding,
            resource_ledger: advanced_ledger,
        };

        let snapshot = self
            .authority
            .snapshot()
            .map_err(map_admission_journal_error)?;
        let commit_sequence = predicted_commit_sequence(snapshot.sequence(), 5)
            .map_err(|_| AdmissionCommitError::InvalidReceipt)?;
        let transaction = transaction_id(b"admission", draft.record_commitment());
        let capacity_request = admission_capacity_request(self.store_binding, draft);
        let capacity = self
            .authority
            .prepare_global_capacity_reservation_v1(capacity_request, transaction)
            .map_err(map_admission_journal_error)?;
        let capacity_reservation = capacity.reservation_id();
        let transaction_commitment = transaction_commitment(
            self.store_binding,
            transaction,
            draft.record_commitment(),
            commit_sequence,
        );
        let receipt = DurableAdmissionCommitV1::new(
            draft.record_commitment(),
            commit_sequence,
            transaction_commitment,
            AdmissionCommitDispositionV1::Created,
        )?;
        let admitted = AdmittedExecutionV1::from_store_commit(draft.clone(), receipt)?;
        let records = vec![
            JournalRecord::put(
                RecordNamespace::Effect,
                admission_key.clone(),
                encode_durable_execution_admission_v1(&admitted),
            ),
            JournalRecord::put(
                RecordNamespace::Effect,
                idempotency_key,
                draft.record_commitment().as_bytes().to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::Effect,
                resource_key,
                admission_resource_value(draft, capacity_reservation),
            ),
            JournalRecord::put(
                RecordNamespace::Effect,
                ADMISSION_AUTHORITY_KEY.to_vec(),
                encode_admission_authority(&advanced_state),
            ),
            capacity.record().clone(),
        ];
        let transaction_record =
            JournalTransaction::new(transaction, records).map_err(map_admission_journal_error)?;
        let preflight = self
            .authority
            .preflight_global_capacity_reservation_v1(&capacity, &transaction_record)
            .map_err(map_admission_journal_error)?;
        match self.authority.commit_global_capacity_reservation_v1(
            &preflight,
            capacity,
            &transaction_record,
        ) {
            Ok((result, _reservation)) if result.commit_sequence == commit_sequence => {
                Ok(AdmissionStoreCommitV1::Committed(receipt))
            }
            Ok((_, _reservation)) => Err(AdmissionCommitError::InvalidReceipt),
            Err(_) => Ok(AdmissionStoreCommitV1::RecoveryRequired(
                ExecutionJournalRecoveryTokenV1 {
                    store_binding: self.store_binding,
                    kind: RecoveryKind::Admission,
                    key: admission_key,
                    transaction,
                    expected_record: draft.record_commitment(),
                    prior_record: None,
                    capacity_reservation: Some(capacity_reservation),
                },
            )),
        }
    }

    fn admission_replay(
        &self,
        draft: &ExecutionAdmissionDraftV1,
        admission_key: &[u8],
        idempotency_key: &[u8],
        resource_key: &[u8],
    ) -> Result<Option<DurableAdmissionCommitV1>, AdmissionCommitError> {
        let admission = self
            .authority
            .get(admission_key)
            .map_err(map_admission_journal_error)?;
        let idempotency = self
            .authority
            .get(idempotency_key)
            .map_err(map_admission_journal_error)?;
        let resource = self
            .authority
            .get(resource_key)
            .map_err(map_admission_journal_error)?;
        match (admission, idempotency, resource) {
            (None, None, None) => Ok(None),
            (Some(bytes), Some(commitment), Some(resource)) => {
                let stored = decode_durable_execution_admission_v1(bytes)
                    .map_err(|_| AdmissionCommitError::CorruptRecord)?;
                let expected_resource = admission_resource_prefix(draft);
                if stored.admission_commitment() != draft.record_commitment()
                    || commitment != draft.record_commitment().as_bytes()
                    || resource.len() != 160
                    || resource.get(..128) != Some(expected_resource.as_slice())
                {
                    return Err(AdmissionCommitError::IdempotencyConflict);
                }
                let capacity_reservation: [u8; 32] = resource[128..160]
                    .try_into()
                    .map_err(|_| AdmissionCommitError::CorruptRecord)?;
                if capacity_reservation == [0; 32] {
                    return Err(AdmissionCommitError::IdempotencyConflict);
                }
                let request = admitted_capacity_request(self.store_binding, &stored);
                let transaction = transaction_id(b"admission", stored.admission_commitment());
                let settlement_is_proven = self
                    .terminal_marker_proves_admission(&stored)
                    .map_err(|_| AdmissionCommitError::CorruptRecord)?;
                match self
                    .authority
                    .lookup_global_capacity_reservation_v1(capacity_reservation)
                    .map_err(map_admission_journal_error)?
                {
                    Some(reservation)
                        if !settlement_is_proven
                            && reservation.matches_request(&request, transaction) => {}
                    None if settlement_is_proven => {}
                    _ => return Err(AdmissionCommitError::IdempotencyConflict),
                }
                DurableAdmissionCommitV1::new(
                    stored.admission_commitment(),
                    stored.journal_sequence(),
                    stored.transaction_commitment(),
                    AdmissionCommitDispositionV1::ExactReplay,
                )
                .map(Some)
            }
            _ => Err(AdmissionCommitError::CorruptRecord),
        }
    }

    fn commit_effect_transition(
        &mut self,
        prior: Option<&DurableExecutionEffectV1>,
        admission: &AdmittedExecutionV1,
        issue: &aos_sandbox_core::runtime_backend::EffectIssueV1,
        phase: EffectPhaseV1,
        completion: Option<&EffectCompletionV1>,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<ExecutionJournalRecoveryTokenV1>, EffectCommitError> {
        let operation_id = issue.idempotency().operation();
        let operation = operation_id.as_bytes();
        let key = effect_key(operation);
        let current = self
            .authority
            .get(&key)
            .map_err(map_effect_journal_error)?
            .map(decode_durable_execution_effect_v1)
            .transpose()
            .map_err(|_| EffectCommitError::CorruptRecord)?;
        match (&current, prior) {
            (Some(stored), _) if stored.record_commitment() == expected_record => {
                let replay = EffectStoreCommitV1::new(
                    expected_record,
                    stored.journal_sequence(),
                    stored.transaction_commitment(),
                    EffectCommitDispositionV1::ExactReplay,
                )?;
                return Ok(EffectStoreTransitionV1::Committed(replay));
            }
            (Some(stored), Some(predecessor))
                if stored.record_commitment() == predecessor.record_commitment()
                    && stored == predecessor => {}
            (None, None) => {}
            (Some(_), None) => return Err(EffectCommitError::IdempotencyConflict),
            (None, Some(_)) => return Err(EffectCommitError::WrongPhase),
            (Some(_), Some(_)) => return Err(EffectCommitError::IdempotencyConflict),
        }
        if matches!(phase, EffectPhaseV1::Pending | EffectPhaseV1::Issued) {
            self.ensure_admission_open(admission)?;
        }
        let mut terminal_reservation = None;
        if phase == EffectPhaseV1::Complete {
            let prior = prior.ok_or(EffectCommitError::WrongPhase)?;
            let completion = completion.ok_or(EffectCommitError::InvalidCompletion)?;
            validate_completion(prior, completion)
                .map_err(|_| EffectCommitError::InvalidCompletion)?;
            if !self
                .authorized_completions
                .contains(&completion_authorization(prior, completion))
            {
                return Err(EffectCommitError::InvalidCompletion);
            }
            if completion_observes_terminal_execution(prior, completion)
                .map_err(|_| EffectCommitError::InvalidCompletion)?
            {
                terminal_reservation = Some(self.load_capacity_reservation(admission)?);
            }
        }

        let mut record_count = 1_usize;
        let sequence_record = if phase == EffectPhaseV1::Pending {
            record_count = 2;
            Some(self.validate_and_encode_sequence(admission, issue)?)
        } else {
            None
        };
        if terminal_reservation.is_some() {
            record_count = record_count
                .checked_add(2)
                .ok_or(EffectCommitError::InvalidReceipt)?;
        }
        let snapshot = self
            .authority
            .snapshot()
            .map_err(map_effect_journal_error)?;
        let commit_sequence = predicted_commit_sequence(snapshot.sequence(), record_count)
            .map_err(|_| EffectCommitError::InvalidReceipt)?;
        let transaction = transaction_id(b"effect", expected_record);
        let transaction_commitment = transaction_commitment(
            self.store_binding,
            transaction,
            expected_record,
            commit_sequence,
        );
        let receipt = EffectStoreCommitV1::new(
            expected_record,
            commit_sequence,
            transaction_commitment,
            EffectCommitDispositionV1::Created,
        )?;
        let candidate = match prior {
            Some(effect) => effect.transitioned_from_store(phase, completion.cloned(), receipt)?,
            None => {
                DurableExecutionEffectV1::pending_from_store(admission.clone(), *issue, receipt)?
            }
        };
        let mut records = Vec::with_capacity(record_count);
        records.push(JournalRecord::put(
            RecordNamespace::Effect,
            key.clone(),
            encode_durable_execution_effect_v1(&candidate),
        ));
        if let Some((sequence_key, sequence_value)) = sequence_record {
            records.push(JournalRecord::put(
                RecordNamespace::Effect,
                sequence_key,
                sequence_value,
            ));
        }
        if let Some(reservation) = &terminal_reservation {
            records.push(JournalRecord::put(
                RecordNamespace::Effect,
                terminal_key(admission.execution()),
                terminal_marker_value(admission, &candidate, reservation.reservation_id()),
            ));
            records.push(reservation.settlement_record());
        }
        let transaction_record =
            JournalTransaction::new(transaction, records).map_err(map_effect_journal_error)?;
        let commit = if let Some(reservation) = terminal_reservation {
            let preflight = self
                .authority
                .preflight_reserved_terminal_v1(&reservation, &transaction_record)
                .map_err(map_effect_journal_error)?;
            self.authority
                .commit_reserved_terminal_v1(&preflight, reservation, &transaction_record)
        } else {
            let preflight = self
                .authority
                .preflight_transactions(std::slice::from_ref(&transaction_record))
                .map_err(map_effect_journal_error)?;
            self.authority
                .validate_preflight_for_effect(
                    &preflight,
                    std::slice::from_ref(&transaction_record),
                )
                .map_err(map_effect_journal_error)?;
            self.authority.commit(&transaction_record)
        };
        match commit {
            Ok(result) if result.commit_sequence == commit_sequence => {
                Ok(EffectStoreTransitionV1::Committed(receipt))
            }
            Ok(_) => Err(EffectCommitError::InvalidReceipt),
            Err(_) => Ok(EffectStoreTransitionV1::RecoveryRequired(
                ExecutionJournalRecoveryTokenV1 {
                    store_binding: self.store_binding,
                    kind: RecoveryKind::Effect,
                    key,
                    transaction,
                    expected_record,
                    prior_record: prior.map(DurableExecutionEffectV1::record_commitment),
                    capacity_reservation: None,
                },
            )),
        }
    }

    fn load_capacity_reservation(
        &self,
        admission: &AdmittedExecutionV1,
    ) -> Result<GlobalCapacityReservationV1, EffectCommitError> {
        let resource = self
            .authority
            .get(&admission_resource_key(admission.execution()))
            .map_err(map_effect_journal_error)?
            .ok_or(EffectCommitError::CorruptRecord)?;
        let expected = admission_resource_prefix_from_admission(admission);
        if resource.len() != 160 || resource.get(..128) != Some(expected.as_slice()) {
            return Err(EffectCommitError::CorruptRecord);
        }
        let reservation_id = resource[128..160]
            .try_into()
            .map_err(|_| EffectCommitError::CorruptRecord)?;
        let reservation = self
            .authority
            .recover_global_capacity_reservation_v1(reservation_id)
            .map_err(map_effect_journal_error)?;
        let transaction = transaction_id(b"admission", admission.admission_commitment());
        if reservation.owner()
            != (
                RecordNamespace::Effect,
                admission_owner_id(admission.execution()),
            )
            || !reservation.matches_request(
                &admitted_capacity_request(self.store_binding, admission),
                transaction,
            )
        {
            return Err(EffectCommitError::CorruptRecord);
        }
        Ok(reservation)
    }

    fn ensure_admission_open(
        &self,
        admission: &AdmittedExecutionV1,
    ) -> Result<(), EffectCommitError> {
        if self
            .authority
            .get(&terminal_key(admission.execution()))
            .map_err(map_effect_journal_error)?
            .is_some()
        {
            return Err(EffectCommitError::StaleAuthority);
        }
        let stored = self
            .authority
            .get(&admission_key(admission.execution()))
            .map_err(map_effect_journal_error)?
            .ok_or(EffectCommitError::StaleAuthority)?;
        let stored = decode_durable_execution_admission_v1(stored)
            .map_err(|_| EffectCommitError::CorruptRecord)?;
        if &stored != admission {
            return Err(EffectCommitError::StaleAuthority);
        }
        let _validated_reservation = self.load_capacity_reservation(admission)?;
        Ok(())
    }

    fn terminal_marker_proves_admission(
        &self,
        admission: &AdmittedExecutionV1,
    ) -> Result<bool, JournalRuntimeExecutionError> {
        let Some(marker) = self.authority.get(&terminal_key(admission.execution()))? else {
            return Ok(false);
        };
        if marker.len() != 112
            || marker.get(..32) != Some(admission.admission_commitment().as_bytes().as_slice())
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let operation: [u8; 16] = marker[32..48]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        let effect_commitment = ObjectDigest::from_bytes(
            marker[48..80]
                .try_into()
                .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
        );
        let reservation: [u8; 32] = marker[80..112]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        let resource = self
            .authority
            .get(&admission_resource_key(admission.execution()))?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let effect = self
            .authority
            .get(&effect_key(&operation))?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let effect = decode_durable_execution_effect_v1(effect)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        let completion = effect
            .completion()
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if resource.len() != 160
            || resource.get(128..160) != Some(reservation.as_slice())
            || effect.admission() != admission
            || effect.record_commitment() != effect_commitment
            || effect.phase() != EffectPhaseV1::Complete
            || !completion_observes_terminal_execution(&effect, completion)?
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        Ok(true)
    }

    fn effect_replay(
        &self,
        key: &[u8],
        expected: ObjectDigest,
    ) -> Result<Option<EffectStoreCommitV1>, EffectCommitError> {
        let Some(bytes) = self.authority.get(key).map_err(map_effect_journal_error)? else {
            return Ok(None);
        };
        let stored = decode_durable_execution_effect_v1(bytes)
            .map_err(|_| EffectCommitError::CorruptRecord)?;
        if stored.record_commitment() != expected {
            return Err(EffectCommitError::IdempotencyConflict);
        }
        EffectStoreCommitV1::new(
            expected,
            stored.journal_sequence(),
            stored.transaction_commitment(),
            EffectCommitDispositionV1::ExactReplay,
        )
        .map(Some)
    }

    fn validate_and_encode_sequence(
        &self,
        admission: &AdmittedExecutionV1,
        issue: &aos_sandbox_core::runtime_backend::EffectIssueV1,
    ) -> Result<(Vec<u8>, Vec<u8>), EffectCommitError> {
        let runtime_handle = admission.currentness().runtime().handle();
        let key = sequence_key(runtime_handle);
        let expected_sequence = self.expected_effect_sequence(runtime_handle)?;
        if issue.sequence().get() != expected_sequence {
            return Err(EffectCommitError::SequenceConflict);
        }
        let mut value = Vec::with_capacity(56);
        value.extend_from_slice(&issue.sequence().get().to_be_bytes());
        value.extend_from_slice(issue.idempotency().operation().as_bytes());
        value.extend_from_slice(effect_issue_anchor(admission, issue).as_bytes());
        Ok((key, value))
    }

    /// Reads the next effect sequence from authenticated protected history.
    pub(crate) fn next_effect_sequence(
        &self,
        runtime_handle: ObjectDigest,
    ) -> Result<
        aos_sandbox_core::runtime_backend::BackendOperationSequenceV1,
        JournalRuntimeExecutionError,
    > {
        let value = self.expected_effect_sequence(runtime_handle)?;
        aos_sandbox_core::runtime_backend::BackendOperationSequenceV1::new(value)
            .map_err(JournalRuntimeExecutionError::from)
    }

    fn expected_effect_sequence(
        &self,
        runtime_handle: ObjectDigest,
    ) -> Result<u64, EffectCommitError> {
        let key = sequence_key(runtime_handle);
        let previous = self.authority.get(&key).map_err(map_effect_journal_error)?;
        let expected_sequence = match previous {
            None => 1,
            Some(bytes) if bytes.len() == 56 => {
                let previous_sequence = u64::from_be_bytes(
                    bytes[..8]
                        .try_into()
                        .map_err(|_| EffectCommitError::CorruptRecord)?,
                );
                let previous_operation: [u8; 16] = bytes[8..24]
                    .try_into()
                    .map_err(|_| EffectCommitError::CorruptRecord)?;
                let previous_issue_anchor = ObjectDigest::from_bytes(
                    bytes[24..56]
                        .try_into()
                        .map_err(|_| EffectCommitError::CorruptRecord)?,
                );
                let previous_effect = self
                    .authority
                    .get(&effect_key(&previous_operation))
                    .map_err(map_effect_journal_error)?
                    .ok_or(EffectCommitError::CorruptRecord)?;
                let previous_effect = decode_durable_execution_effect_v1(previous_effect)
                    .map_err(|_| EffectCommitError::CorruptRecord)?;
                if previous_effect.phase() != EffectPhaseV1::Complete
                    || effect_issue_anchor(previous_effect.admission(), previous_effect.issue())
                        != previous_issue_anchor
                    || previous_effect.issue().sequence().get() != previous_sequence
                    || previous_effect.admission().currentness().runtime().handle()
                        != runtime_handle
                    || previous_effect.issue().idempotency().operation().as_bytes()
                        != &previous_operation
                {
                    return Err(EffectCommitError::CorruptRecord);
                }
                previous_sequence
                    .checked_add(1)
                    .ok_or(EffectCommitError::SequenceConflict)?
            }
            Some(_) => return Err(EffectCommitError::CorruptRecord),
        };
        Ok(expected_sequence)
    }
}

impl ExecutionAdmissionStore for JournalRuntimeExecutionStoreV1<'_> {
    type RecoveryToken = ExecutionJournalRecoveryTokenV1;

    fn commit_execution_admission(
        &mut self,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError> {
        self.commit_admission(draft)
    }

    fn recover_execution_admission(
        &mut self,
        token: Self::RecoveryToken,
        draft: &ExecutionAdmissionDraftV1,
    ) -> Result<AdmissionStoreCommitV1<Self::RecoveryToken>, AdmissionCommitError> {
        if token.store_binding != self.store_binding
            || token.kind != RecoveryKind::Admission
            || token.expected_record != draft.record_commitment()
            || token.transaction != transaction_id(b"admission", draft.record_commitment())
            || token.key != admission_key(draft.execution())
            || token.prior_record.is_some()
            || token.capacity_reservation.is_none()
        {
            return Err(AdmissionCommitError::ReceiptMismatch);
        }
        let idempotency_key = admission_idempotency_key(draft.idempotency().operation().as_bytes());
        let resource_key = admission_resource_key(draft.execution());
        match self.admission_replay(draft, &token.key, &idempotency_key, &resource_key)? {
            Some(receipt) => {
                let resource = self
                    .authority
                    .get(&resource_key)
                    .map_err(map_admission_journal_error)?
                    .ok_or(AdmissionCommitError::CorruptRecord)?;
                if resource.get(128..160)
                    != token
                        .capacity_reservation
                        .as_ref()
                        .map(|value| value.as_slice())
                {
                    return Err(AdmissionCommitError::ReceiptMismatch);
                }
                Ok(AdmissionStoreCommitV1::Committed(receipt))
            }
            None => Ok(AdmissionStoreCommitV1::NotCommitted),
        }
    }
}

impl ExecutionEffectStore for JournalRuntimeExecutionStoreV1<'_> {
    type RecoveryToken = ExecutionJournalRecoveryTokenV1;

    fn commit_pending_effect(
        &mut self,
        admission: &AdmittedExecutionV1,
        issue: &aos_sandbox_core::runtime_backend::EffectIssueV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.commit_effect_transition(
            None,
            admission,
            issue,
            EffectPhaseV1::Pending,
            None,
            expected_record,
        )
    }

    fn commit_effect_issued(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        let transition = self.commit_effect_transition(
            Some(effect),
            effect.admission(),
            effect.issue(),
            EffectPhaseV1::Issued,
            None,
            expected_record,
        )?;
        if let EffectStoreTransitionV1::Committed(receipt) = &transition {
            if receipt.disposition() == EffectCommitDispositionV1::Created {
                self.freshly_issued
                    .insert(*effect.issue().idempotency().operation().as_bytes());
            }
        }
        Ok(transition)
    }

    fn commit_effect_indeterminate(
        &mut self,
        effect: &DurableExecutionEffectV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.commit_effect_transition(
            Some(effect),
            effect.admission(),
            effect.issue(),
            EffectPhaseV1::Indeterminate,
            None,
            expected_record,
        )
    }

    fn commit_effect_complete(
        &mut self,
        effect: &DurableExecutionEffectV1,
        completion: &EffectCompletionV1,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        self.commit_effect_transition(
            Some(effect),
            effect.admission(),
            effect.issue(),
            EffectPhaseV1::Complete,
            Some(completion),
            expected_record,
        )
    }

    fn recover_effect_transition(
        &mut self,
        token: Self::RecoveryToken,
        expected_record: ObjectDigest,
    ) -> Result<EffectStoreTransitionV1<Self::RecoveryToken>, EffectCommitError> {
        if token.store_binding != self.store_binding
            || token.kind != RecoveryKind::Effect
            || token.expected_record != expected_record
            || token.transaction != transaction_id(b"effect", expected_record)
            || token.capacity_reservation.is_some()
        {
            return Err(EffectCommitError::ReceiptMismatch);
        }
        match self.effect_replay(&token.key, expected_record) {
            Ok(Some(receipt)) => Ok(EffectStoreTransitionV1::Committed(receipt)),
            Ok(None) if token.prior_record.is_none() => Ok(EffectStoreTransitionV1::NotCommitted),
            Err(EffectCommitError::IdempotencyConflict) => {
                let Some(prior_record) = token.prior_record else {
                    return Err(EffectCommitError::IdempotencyConflict);
                };
                let stored = self
                    .authority
                    .get(&token.key)
                    .map_err(map_effect_journal_error)?
                    .ok_or(EffectCommitError::CorruptRecord)?;
                let stored = decode_durable_execution_effect_v1(stored)
                    .map_err(|_| EffectCommitError::CorruptRecord)?;
                if stored.record_commitment() != prior_record {
                    return Err(EffectCommitError::IdempotencyConflict);
                }
                Ok(EffectStoreTransitionV1::NotCommitted)
            }
            Ok(None) => Err(EffectCommitError::CorruptRecord),
            Err(error) => Err(error),
        }
    }
}

fn admission_key(execution: ExecutionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(ADMISSION_KEY_PREFIX);
    key.extend_from_slice(execution.as_bytes());
    key
}

fn agent_outcome_key(operation: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(AGENT_OUTCOME_KEY_PREFIX);
    key.extend_from_slice(operation);
    key
}

fn owned_key(key: &[u8]) -> bool {
    key == STORE_MARKER_KEY
        || key == ADMISSION_AUTHORITY_KEY
        || key == OUTPUT_FORMAT_KEY
        || output_record_key(key)
        || matches!(
            key,
            [ADMISSION_KEY_PREFIX | ADMISSION_IDEMPOTENCY_KEY_PREFIX | ADMISSION_RESOURCE_KEY_PREFIX | EFFECT_KEY_PREFIX | TERMINAL_KEY_PREFIX, ..]
                if key.len() == 17
        )
        || matches!(key, [SEQUENCE_KEY_PREFIX, ..] if key.len() == 33)
        || matches!(key, [ROUTE_KEY_PREFIX, ..] if key.len() == 17)
        || matches!(key, [AGENT_OUTCOME_KEY_PREFIX, ..] if key.len() == 17)
        || matches!(key, [ARGUMENT_KEY_PREFIX, ..] if key.len() == 17)
        || matches!(key, [HOST_OUTPUT_KEY_PREFIX, ..] if key.len() == 17)
}

fn output_record_key(key: &[u8]) -> bool {
    key == OUTPUT_MARKER_KEY || matches!(key, [CLAIM_KEY_PREFIX, ..] if key.len() == 17)
}

fn output_format_bytes(store_binding: ObjectDigest) -> [u8; 40] {
    let mut bytes = [0_u8; 40];
    bytes[..8].copy_from_slice(OUTPUT_FORMAT_MAGIC);
    bytes[8..].copy_from_slice(store_binding.as_bytes());
    bytes
}

fn host_output_receipt(
    correlation: HostOutputCorrelationV1,
) -> Result<ProtectedHostOutputReservationV1, JournalRuntimeExecutionError> {
    let bytes = correlation
        .encode()
        .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
    let correlation_digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
    Ok(ProtectedHostOutputReservationV1 {
        execution: correlation.execution,
        create_operation: correlation.create_operation,
        preissue_digest: correlation.preissue_digest,
        claim_digest: correlation.claim_digest,
        carrier_digest: correlation.carrier_digest,
        original_request_id: correlation.original_request_id,
        assignment_digest: correlation.assignment_digest,
        host_boot_id: correlation.host_boot_id,
        plan_digest: correlation.plan_digest,
        semantic_request_digest: correlation.semantic_request_digest,
        correlation_digest,
        original_journal_sequence: correlation.original_journal_sequence,
    })
}

fn validate_runtime_execution_replay(
    authority: &ProtectedJournalAuthority<'_>,
    store_binding: ObjectDigest,
    agent_peer: ProtectedAgentRoutePeerV1,
) -> Result<(), JournalRuntimeExecutionError> {
    let protected_sequence = authority.snapshot()?.sequence();
    let mut marker_seen = false;
    let mut output_format_seen = false;
    let mut output_marker = None;
    let mut provisional_claims = BTreeMap::new();
    let mut host_output_correlations = BTreeMap::new();
    let mut argument_observations = BTreeMap::new();
    let mut admission_state = None;
    let mut admissions = BTreeMap::new();
    let mut idempotency = BTreeMap::new();
    let mut resources = BTreeMap::new();
    let mut effects = BTreeMap::new();
    let mut routes = BTreeMap::new();
    let mut agent_outcomes = BTreeMap::new();
    let mut sequence_heads = BTreeMap::new();
    let mut terminals = BTreeMap::new();
    let mut record_count = 0_usize;

    for (key, value) in authority.records()? {
        record_count = record_count
            .checked_add(1)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if record_count > MAXIMUM_RUNTIME_EXECUTION_RECORDS || !owned_key(key) {
            return Err(JournalRuntimeExecutionError::ForeignStore);
        }
        if key == STORE_MARKER_KEY {
            if marker_seen || value != store_binding.as_bytes() {
                return Err(JournalRuntimeExecutionError::ForeignStore);
            }
            marker_seen = true;
            continue;
        }
        if key == ADMISSION_AUTHORITY_KEY {
            if admission_state
                .replace(decode_admission_authority(value)?)
                .is_some()
            {
                return Err(JournalRuntimeExecutionError::CorruptRecord);
            }
            continue;
        }
        if key == OUTPUT_FORMAT_KEY {
            if output_format_seen || value != output_format_bytes(store_binding) {
                return Err(JournalRuntimeExecutionError::CorruptRecord);
            }
            output_format_seen = true;
            continue;
        }
        if key == OUTPUT_MARKER_KEY {
            if output_marker.replace(value.to_vec()).is_some() {
                return Err(JournalRuntimeExecutionError::CorruptRecord);
            }
            continue;
        }

        let suffix = key
            .get(1..)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        match key.first().copied() {
            Some(CLAIM_KEY_PREFIX) if key.len() == 17 => {
                let retained = decode_claim(value)?;
                if retained.execution.as_slice() != suffix
                    || provisional_claims
                        .insert(key.to_vec(), value.to_vec())
                        .is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(HOST_OUTPUT_KEY_PREFIX) if key.len() == 17 => {
                let correlation = HostOutputCorrelationV1::decode(value)
                    .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
                if correlation.execution.as_bytes() != suffix
                    || correlation.original_journal_sequence > protected_sequence
                    || host_output_correlations
                        .insert(correlation.execution, correlation)
                        .is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(ARGUMENT_KEY_PREFIX) if key.len() == 17 => {
                let record = ArgumentObservationRecordV1::decode(value)
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                if record.execution.as_bytes() != suffix
                    || argument_observations
                        .insert(record.execution, record)
                        .is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(ADMISSION_KEY_PREFIX) if key.len() == 17 => {
                let admission = decode_durable_execution_admission_v1(value)
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                if admission_key(admission.execution()) != key
                    || encode_durable_execution_admission_v1(&admission) != value
                    || admissions
                        .insert(*admission.execution().as_bytes(), admission)
                        .is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(ADMISSION_IDEMPOTENCY_KEY_PREFIX) if key.len() == 17 => {
                let operation: [u8; 16] = suffix
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                let commitment = ObjectDigest::from_bytes(
                    value
                        .try_into()
                        .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
                );
                if operation == [0; 16]
                    || commitment.as_bytes() == &[0; 32]
                    || idempotency.insert(operation, commitment).is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(ADMISSION_RESOURCE_KEY_PREFIX) if key.len() == 17 => {
                let execution: [u8; 16] = suffix
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                if execution == [0; 16]
                    || value.len() != 160
                    || value.chunks_exact(32).any(|digest| digest == [0_u8; 32])
                    || resources.insert(execution, value.to_vec()).is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(EFFECT_KEY_PREFIX) if key.len() == 17 => {
                let effect = decode_durable_execution_effect_v1(value)
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                let operation = *effect.issue().idempotency().operation().as_bytes();
                if operation.as_slice() != suffix
                    || effect_key(&operation) != key
                    || encode_durable_execution_effect_v1(&effect) != value
                    || effects.insert(operation, effect).is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(ROUTE_KEY_PREFIX) if key.len() == 17 => {
                let route = ProtectedAgentRouteRecordV1::decode(value)?;
                let operation = *route.request().operation_id().as_bytes();
                if route_key(&operation) != key || routes.insert(operation, route).is_some() {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(AGENT_OUTCOME_KEY_PREFIX) if key.len() == 17 => {
                let record = HostAgentOutcomeRecordV1::decode(value)?;
                let operation = *record.packet().outcome().operation_id().as_bytes();
                if agent_outcome_key(&operation) != key
                    || agent_outcomes.insert(operation, record).is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(SEQUENCE_KEY_PREFIX) if key.len() == 33 => {
                let runtime_handle: [u8; 32] = suffix
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                let head = decode_runtime_sequence_head(value)?;
                if runtime_handle == [0; 32]
                    || sequence_heads.insert(runtime_handle, head).is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            Some(TERMINAL_KEY_PREFIX) if key.len() == 17 => {
                let execution: [u8; 16] = suffix
                    .try_into()
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
                if execution == [0; 16]
                    || value.len() != 112
                    || terminals.insert(execution, value.to_vec()).is_some()
                {
                    return Err(JournalRuntimeExecutionError::CorruptRecord);
                }
            }
            _ => return Err(JournalRuntimeExecutionError::ForeignStore),
        }
    }
    if !marker_seen {
        return Err(JournalRuntimeExecutionError::UninitializedStore);
    }
    let admission_state =
        admission_state.ok_or(JournalRuntimeExecutionError::UninitializedStore)?;
    if output_format_seen {
        let marker = output_marker
            .as_deref()
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let (first_key, first_bytes) = provisional_claims
            .first_key_value()
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let first = decode_claim(first_bytes)?;
        replay_ledger(
            std::iter::once((OUTPUT_MARKER_KEY, marker)).chain(
                provisional_claims
                    .iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
            ),
            first.assignment,
            first.parent_bytes,
            first_key,
            first_bytes,
        )?;
    } else if output_marker.is_some() || !provisional_claims.is_empty() {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }
    for (execution, correlation) in &host_output_correlations {
        let claim_bytes = provisional_claims
            .get(&claim_key(*execution))
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let claim = decode_claim(claim_bytes)?;
        if claim.create_operation != *correlation.create_operation.as_bytes()
            || claim.assignment != correlation.assignment_digest
            || claim.record_digest != correlation.claim_digest
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
    }
    for (execution, record) in &argument_observations {
        let retained = provisional_claims
            .get(&claim_key(*execution))
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)
            .and_then(|bytes| decode_claim(bytes).map_err(Into::into))?;
        if retained.create_operation != *record.create_operation.as_bytes()
            || retained.assignment != record.request.runtime().assignment_digest()
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
    }
    if admissions.len() != idempotency.len() || admissions.len() != resources.len() {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }

    let mut ordered_admissions: Vec<&AdmittedExecutionV1> = admissions.values().collect();
    ordered_admissions.sort_by_key(|admission| admission.journal_sequence());
    let mut prior_journal_sequence = None;
    let mut resource_ledger = None;
    let mut current_reservations = BTreeSet::new();
    let mut all_reservations = BTreeSet::new();
    let mut admission_commitments = BTreeSet::new();
    let mut durable_sequences = BTreeSet::new();
    let mut output_budget: Option<OutputBudget> = None;
    for admission in ordered_admissions {
        if admission.journal_sequence() > protected_sequence
            || !durable_sequences.insert(admission.journal_sequence())
            || !admission_commitments.insert(*admission.admission_commitment().as_bytes())
            || prior_journal_sequence.is_some_and(|prior| prior >= admission.journal_sequence())
            || admission.transaction_commitment()
                != transaction_commitment(
                    store_binding,
                    transaction_id(b"admission", admission.admission_commitment()),
                    admission.admission_commitment(),
                    admission.journal_sequence(),
                )
            || admission_authority_binding(admission.currentness())
                != admission_state.authority_binding
            || resource_ledger
                .is_some_and(|prior| prior != admission.currentness().resource_ledger())
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let operation = *admission.idempotency().operation().as_bytes();
        let claim = decode_output_claim(admission.specification_bytes())
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        if output_format_seen {
            let retained = provisional_claims
                .get(&claim_key(admission.execution()))
                .ok_or(JournalRuntimeExecutionError::CorruptRecord)
                .and_then(|bytes| decode_claim(bytes).map_err(Into::into))?;
            if !claim.matches_provisional(
                &retained,
                admission.execution().as_bytes(),
                &operation,
                admission.currentness().output_reservation(),
            ) {
                return Err(JournalRuntimeExecutionError::CorruptRecord);
            }
        } else {
            match output_budget.as_mut() {
                Some(budget) => budget
                    .include(claim)
                    .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
                None => {
                    output_budget = Some(
                        OutputBudget::from_first(claim)
                            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
                    );
                }
            }
        }
        if idempotency.get(&operation) != Some(&admission.admission_commitment()) {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let execution = *admission.execution().as_bytes();
        let resource = resources
            .get(&execution)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let expected_resource = admission_resource_prefix_from_admission(admission);
        if resource.get(..128) != Some(expected_resource.as_slice()) {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let reservation_id: [u8; 32] = resource[128..160]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        if !all_reservations.insert(reservation_id) {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        let terminal = terminals.contains_key(&execution);
        match authority.lookup_global_capacity_reservation_v1(reservation_id)? {
            Some(reservation)
                if !terminal
                    && reservation.matches_request(
                        &admitted_capacity_request(store_binding, admission),
                        transaction_id(b"admission", admission.admission_commitment()),
                    )
                    && current_reservations.insert(reservation_id) => {}
            None if terminal => {}
            _ => return Err(JournalRuntimeExecutionError::CorruptRecord),
        }
        prior_journal_sequence = Some(admission.journal_sequence());
        resource_ledger = Some(advance_admitted_resource_ledger(admission));
    }
    if resource_ledger.is_some_and(|ledger| ledger != admission_state.resource_ledger) {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }

    let mut effects_by_runtime: BTreeMap<[u8; 32], Vec<&DurableExecutionEffectV1>> =
        BTreeMap::new();
    let mut terminal_effect_by_execution = BTreeMap::new();
    let mut effect_commitments = BTreeSet::new();
    for (operation, effect) in &effects {
        let execution = *effect.admission().execution().as_bytes();
        let admission = admissions
            .get(&execution)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if effect.journal_sequence() > protected_sequence
            || !durable_sequences.insert(effect.journal_sequence())
            || !effect_commitments.insert(*effect.record_commitment().as_bytes())
            || effect.admission() != admission
            || effect.issue().idempotency().operation().as_bytes() != operation
            || effect.journal_sequence() <= admission.journal_sequence()
            || effect.transaction_commitment()
                != transaction_commitment(
                    store_binding,
                    transaction_id(b"effect", effect.record_commitment()),
                    effect.record_commitment(),
                    effect.journal_sequence(),
                )
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
        if let Some(completion) = effect.completion() {
            validate_completion(effect, completion)?;
            if completion_observes_terminal_execution(effect, completion)?
                && terminal_effect_by_execution
                    .insert(execution, *operation)
                    .is_some()
            {
                return Err(JournalRuntimeExecutionError::CorruptRecord);
            }
        }
        effects_by_runtime
            .entry(
                *effect
                    .admission()
                    .currentness()
                    .runtime()
                    .handle()
                    .as_bytes(),
            )
            .or_default()
            .push(effect);
    }
    for (operation, route) in &routes {
        let effect = effects
            .get(operation)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        route.validate_effect(effect, false)?;
        route.validate_peer(agent_peer)?;
    }
    let mut outcome_observation_sequences = BTreeSet::new();
    for (operation, record) in &agent_outcomes {
        let route = routes
            .get(operation)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        route.validate_signed_outcome(record.packet(), agent_peer)?;
        if !outcome_observation_sequences.insert(record.observation_sequence().get()) {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
    }
    if effects_by_runtime.len() != sequence_heads.len()
        || terminal_effect_by_execution.len() != terminals.len()
    {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }
    for (runtime_handle, runtime_effects) in &mut effects_by_runtime {
        runtime_effects.sort_by_key(|effect| effect.issue().sequence().get());
        let head = sequence_heads
            .get(runtime_handle)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let effect_count = runtime_effects.len();
        for (index, effect) in runtime_effects.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
            if effect.issue().sequence().get() != expected_sequence
                || (index + 1 != effect_count && effect.phase() != EffectPhaseV1::Complete)
            {
                return Err(JournalRuntimeExecutionError::CorruptRecord);
            }
            if terminal_effect_by_execution
                .get(effect.admission().execution().as_bytes())
                .is_some_and(|terminal_operation| {
                    terminal_operation != effect.issue().idempotency().operation().as_bytes()
                        && effects
                            .get(terminal_operation)
                            .is_some_and(|terminal_effect| {
                                terminal_effect.issue().sequence().get()
                                    < effect.issue().sequence().get()
                            })
                })
            {
                return Err(JournalRuntimeExecutionError::CorruptRecord);
            }
        }
        let latest = runtime_effects
            .last()
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if head.sequence != latest.issue().sequence().get()
            || head.operation != *latest.issue().idempotency().operation().as_bytes()
            || head.issue_anchor != effect_issue_anchor(latest.admission(), latest.issue())
            || latest
                .admission()
                .currentness()
                .runtime()
                .handle()
                .as_bytes()
                != runtime_handle
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
    }

    for (execution, marker) in &terminals {
        let admission = admissions
            .get(execution)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let operation = terminal_effect_by_execution
            .get(execution)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let effect = effects
            .get(operation)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let resource = resources
            .get(execution)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        if marker.get(..32) != Some(admission.admission_commitment().as_bytes().as_slice())
            || marker.get(32..48) != Some(operation.as_slice())
            || marker.get(48..80) != Some(effect.record_commitment().as_bytes().as_slice())
            || marker.get(80..112) != resource.get(128..160)
            || effect.phase() != EffectPhaseV1::Complete
            || effect.admission() != admission
        {
            return Err(JournalRuntimeExecutionError::CorruptRecord);
        }
    }
    authority.validate_global_capacity_reservation_set_v1(&current_reservations)?;
    Ok(())
}

struct RuntimeSequenceHeadV1 {
    sequence: u64,
    operation: [u8; 16],
    issue_anchor: ObjectDigest,
}

fn decode_runtime_sequence_head(
    bytes: &[u8],
) -> Result<RuntimeSequenceHeadV1, JournalRuntimeExecutionError> {
    if bytes.len() != 56 {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }
    let sequence = u64::from_be_bytes(
        bytes[0..8]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
    );
    let operation = bytes[8..24]
        .try_into()
        .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
    let issue_anchor = ObjectDigest::from_bytes(
        bytes[24..56]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
    );
    if sequence == 0 || operation == [0; 16] || issue_anchor.as_bytes() == &[0; 32] {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }
    Ok(RuntimeSequenceHeadV1 {
        sequence,
        operation,
        issue_anchor,
    })
}

fn admission_idempotency_key(operation: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(ADMISSION_IDEMPOTENCY_KEY_PREFIX);
    key.extend_from_slice(operation);
    key
}

fn admission_resource_key(execution: ExecutionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(ADMISSION_RESOURCE_KEY_PREFIX);
    key.extend_from_slice(execution.as_bytes());
    key
}

fn admission_resource_prefix(draft: &ExecutionAdmissionDraftV1) -> Vec<u8> {
    let mut value = Vec::with_capacity(128);
    value.extend_from_slice(draft.currentness().resource_ledger().as_bytes());
    value.extend_from_slice(draft.currentness().output_reservation().as_bytes());
    value.extend_from_slice(advance_resource_ledger(draft).as_bytes());
    value.extend_from_slice(draft.record_commitment().as_bytes());
    value
}

fn admission_resource_value(
    draft: &ExecutionAdmissionDraftV1,
    capacity_reservation: [u8; 32],
) -> Vec<u8> {
    let mut value = admission_resource_prefix(draft);
    value.extend_from_slice(&capacity_reservation);
    value
}

fn admission_resource_prefix_from_admission(admission: &AdmittedExecutionV1) -> Vec<u8> {
    let mut value = Vec::with_capacity(128);
    value.extend_from_slice(admission.currentness().resource_ledger().as_bytes());
    value.extend_from_slice(admission.currentness().output_reservation().as_bytes());
    value.extend_from_slice(advance_admitted_resource_ledger(admission).as_bytes());
    value.extend_from_slice(admission.admission_commitment().as_bytes());
    value
}

fn admission_capacity_request(
    store_binding: ObjectDigest,
    draft: &ExecutionAdmissionDraftV1,
) -> GlobalCapacityReservationRequestV1 {
    GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::RuntimeExecution,
        owner_namespace: RecordNamespace::Effect,
        owner_id: admission_owner_id(draft.execution()),
        owner_digest: *store_binding.as_bytes(),
        operation_id: *draft.idempotency().operation().as_bytes(),
        artifact_digest: *draft.specification_digest().as_bytes(),
        checkpoint_digest: *draft.record_commitment().as_bytes(),
        chain_head_digest: *draft.currentness().resource_ledger().as_bytes(),
        terminal_records: TERMINAL_CAPACITY_RECORDS,
        terminal_bytes: TERMINAL_CAPACITY_BYTES,
        poison_records: TERMINAL_CAPACITY_RECORDS,
        poison_bytes: TERMINAL_CAPACITY_BYTES,
    }
}

fn admitted_capacity_request(
    store_binding: ObjectDigest,
    admission: &AdmittedExecutionV1,
) -> GlobalCapacityReservationRequestV1 {
    GlobalCapacityReservationRequestV1 {
        purpose: GlobalCapacityReservationPurposeV1::RuntimeExecution,
        owner_namespace: RecordNamespace::Effect,
        owner_id: admission_owner_id(admission.execution()),
        owner_digest: *store_binding.as_bytes(),
        operation_id: *admission.idempotency().operation().as_bytes(),
        artifact_digest: *admission.specification_digest().as_bytes(),
        checkpoint_digest: *admission.admission_commitment().as_bytes(),
        chain_head_digest: *admission.currentness().resource_ledger().as_bytes(),
        terminal_records: TERMINAL_CAPACITY_RECORDS,
        terminal_bytes: TERMINAL_CAPACITY_BYTES,
        poison_records: TERMINAL_CAPACITY_RECORDS,
        poison_bytes: TERMINAL_CAPACITY_BYTES,
    }
}

fn admission_owner_id(execution: ExecutionId) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-capacity-owner-v1\0");
    digest.update(execution.as_bytes());
    digest.finalize().into()
}

fn admission_authority_binding(currentness: &AdmissionCurrentnessV1) -> ObjectDigest {
    let runtime = currentness.runtime();
    let probe = currentness.backend_probe();
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-protected-execution-admission-authority-v1\0");
    digest.update(runtime.currentness().sandbox().as_bytes());
    digest.update(runtime.currentness().incarnation().as_bytes());
    digest.update(runtime.currentness().node().as_bytes());
    digest.update(runtime.currentness().assignment_epoch().get().to_be_bytes());
    digest.update(runtime.currentness().assignment_digest().as_bytes());
    digest.update(
        runtime
            .currentness()
            .desired_generation()
            .get()
            .to_be_bytes(),
    );
    digest.update(
        runtime
            .currentness()
            .namespace_generation()
            .get()
            .to_be_bytes(),
    );
    digest.update(runtime.plan_commitment().as_bytes());
    digest.update(runtime.handle().as_bytes());
    digest.update(currentness.payload_boot_id().as_bytes());
    digest.update(probe.node().as_bytes());
    digest.update(probe.backend_build().as_bytes());
    digest.update(probe.probe_epoch().get().to_be_bytes());
    digest.update(probe.protected_context().as_bytes());
    digest.update(currentness.authority_context().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn advance_resource_ledger(draft: &ExecutionAdmissionDraftV1) -> ObjectDigest {
    advance_resource_ledger_fields(
        draft.currentness().resource_ledger(),
        draft.execution(),
        draft.currentness().output_reservation(),
        draft.record_commitment(),
    )
}

fn advance_admitted_resource_ledger(admission: &AdmittedExecutionV1) -> ObjectDigest {
    advance_resource_ledger_fields(
        admission.currentness().resource_ledger(),
        admission.execution(),
        admission.currentness().output_reservation(),
        admission.admission_commitment(),
    )
}

fn advance_resource_ledger_fields(
    previous: ObjectDigest,
    execution: ExecutionId,
    reservation: ObjectDigest,
    admission: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-execution-resource-ledger-v1\0");
    digest.update(previous.as_bytes());
    digest.update(execution.as_bytes());
    digest.update(reservation.as_bytes());
    digest.update(admission.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn encode_admission_authority(state: &ProtectedExecutionAdmissionStateV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(ADMISSION_AUTHORITY_MAGIC);
    bytes.extend_from_slice(state.authority_binding.as_bytes());
    bytes.extend_from_slice(state.resource_ledger.as_bytes());
    bytes
}

fn decode_admission_authority(
    bytes: &[u8],
) -> Result<ProtectedExecutionAdmissionStateV1, JournalRuntimeExecutionError> {
    if bytes.len() != 72 || bytes.get(..8) != Some(ADMISSION_AUTHORITY_MAGIC.as_slice()) {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }
    let authority_binding = ObjectDigest::from_bytes(
        bytes[8..40]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
    );
    let resource_ledger = ObjectDigest::from_bytes(
        bytes[40..72]
            .try_into()
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?,
    );
    if authority_binding.as_bytes() == &[0; 32] || resource_ledger.as_bytes() == &[0; 32] {
        return Err(JournalRuntimeExecutionError::CorruptRecord);
    }
    Ok(ProtectedExecutionAdmissionStateV1 {
        authority_binding,
        resource_ledger,
    })
}

fn effect_key(operation: &[u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(EFFECT_KEY_PREFIX);
    key.extend_from_slice(operation);
    key
}

fn terminal_key(execution: ExecutionId) -> Vec<u8> {
    let mut key = Vec::with_capacity(17);
    key.push(TERMINAL_KEY_PREFIX);
    key.extend_from_slice(execution.as_bytes());
    key
}

fn terminal_marker_value(
    admission: &AdmittedExecutionV1,
    effect: &DurableExecutionEffectV1,
    capacity_reservation: [u8; 32],
) -> Vec<u8> {
    let mut value = Vec::with_capacity(112);
    value.extend_from_slice(admission.admission_commitment().as_bytes());
    value.extend_from_slice(effect.issue().idempotency().operation().as_bytes());
    value.extend_from_slice(effect.record_commitment().as_bytes());
    value.extend_from_slice(&capacity_reservation);
    value
}

fn effect_issue_anchor(
    admission: &AdmittedExecutionV1,
    issue: &aos_sandbox_core::runtime_backend::EffectIssueV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-issue-anchor-v1\0");
    digest.update(admission.admission_commitment().as_bytes());
    digest.update(
        admission
            .currentness()
            .runtime()
            .plan_commitment()
            .as_bytes(),
    );
    digest.update(admission.currentness().runtime().handle().as_bytes());
    digest.update(issue.idempotency().operation().as_bytes());
    digest.update(issue.idempotency().request_digest().as_bytes());
    digest.update(issue.sequence().get().to_be_bytes());
    digest.update([issue.operation().code()]);
    digest.update(issue.operation().arguments());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn sequence_key(runtime_handle: ObjectDigest) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(SEQUENCE_KEY_PREFIX);
    key.extend_from_slice(runtime_handle.as_bytes());
    key
}

fn predicted_commit_sequence(current: u64, records: usize) -> Result<u64, JournalError> {
    let record_count = u64::try_from(records).map_err(|_| JournalError::SequenceExhausted)?;
    current
        .checked_add(record_count)
        .and_then(|value| value.checked_add(1))
        .ok_or(JournalError::SequenceExhausted)
}

fn transaction_id(domain: &[u8], record: ObjectDigest) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-transaction-v1\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update(record.as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&hash[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    id
}

fn transaction_commitment(
    store_binding: ObjectDigest,
    transaction: [u8; 16],
    record: ObjectDigest,
    sequence: u64,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-journal-commit-v1\0");
    digest.update(store_binding.as_bytes());
    digest.update(transaction);
    digest.update(record.as_bytes());
    digest.update(sequence.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn snapshot_commitment(store_binding: ObjectDigest, sequence: u64) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-journal-head-v1\0");
    digest.update(store_binding.as_bytes());
    digest.update(sequence.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn record_provenance(
    store_binding: ObjectDigest,
    sequence: u64,
    record: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-record-provenance-v1\0");
    digest.update(store_binding.as_bytes());
    digest.update(sequence.to_be_bytes());
    digest.update(record.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn completion_authorization(
    effect: &DurableExecutionEffectV1,
    completion: &EffectCompletionV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-runtime-execution-completion-authorization-v1\0");
    digest.update(effect.record_commitment().as_bytes());
    digest.update(completion.result_digest().as_bytes());
    digest.update(completion.observation_sequence().get().to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn map_admission_journal_error(error: JournalError) -> AdmissionCommitError {
    match error {
        JournalError::IdempotencyConflict => AdmissionCommitError::IdempotencyConflict,
        JournalError::LimitExceeded(_) => AdmissionCommitError::CapacityUnavailable,
        JournalError::Poisoned => AdmissionCommitError::CorruptRecord,
        _ => AdmissionCommitError::StaleAuthority,
    }
}

fn map_effect_journal_error(error: JournalError) -> EffectCommitError {
    match error {
        JournalError::IdempotencyConflict => EffectCommitError::IdempotencyConflict,
        JournalError::SequenceExhausted => EffectCommitError::SequenceConflict,
        JournalError::Poisoned => EffectCommitError::CorruptRecord,
        _ => EffectCommitError::StaleAuthority,
    }
}

/// Reports protected execution-journal, evidence, or dispatch failure.
#[derive(Debug, thiserror::Error)]
pub enum JournalRuntimeExecutionError {
    /// An argument-observation append may have committed; cold reopen is required.
    #[error("runtime argument observation outcome is unknown; reopen protected custody")]
    ObservationOutcomeUnknown,
    /// The configured store binding is zero or does not match a permit.
    #[error("runtime execution store binding is invalid")]
    InvalidBinding,
    /// Initialization was requested for a nonempty authority journal.
    #[error("runtime execution store is already initialized")]
    AlreadyInitialized,
    /// The protected journal has no execution-owner marker.
    #[error("runtime execution store is not initialized")]
    UninitializedStore,
    /// The protected journal belongs to another owner or contains foreign keys.
    #[error("runtime execution journal is not dedicated to this store")]
    ForeignStore,
    /// The requested durable admission or effect is absent.
    #[error("runtime execution durable record is absent")]
    MissingRecord,
    /// Recovery requires an authenticated complete backend inventory.
    #[error("runtime execution recovery inventory is absent")]
    MissingInventory,
    /// A durable record is malformed or contradicts its commitments.
    #[error("runtime execution durable record is corrupt")]
    CorruptRecord,
    /// Current protected bytes differ from the supplied record.
    #[error("runtime execution durable record conflicts")]
    RecordConflict,
    /// The effect is not in the required durable phase.
    #[error("runtime execution effect is in the wrong phase")]
    WrongPhase,
    /// The effect operation cannot cross this backend boundary.
    #[error("runtime execution operation cannot be dispatched")]
    WrongOperation,
    /// This store instance already minted the one allowed dispatch permit.
    #[error("runtime execution dispatch permit was already consumed")]
    DispatchAlreadyConsumed,
    /// The record predates this live process and is recovery-only.
    #[error("runtime execution effect requires recovery instead of redispatch")]
    RecoveryOnly,
    /// Protected journal access or durability failed.
    #[error("runtime execution protected journal failed: {0}")]
    Journal(#[from] JournalError),
    /// Accepted Create output source or provisional reservation failed.
    #[error("runtime execution output reservation failed: {0}")]
    OutputReservation(#[from] ExecutionOutputReservationErrorV1),
    /// Portable admission failed.
    #[error("runtime execution admission failed: {0}")]
    Admission(#[from] AdmissionCommitError),
    /// Portable effect transition failed.
    #[error("runtime execution effect failed: {0}")]
    Effect(#[from] EffectCommitError),
    /// Operation-specific completion evidence failed.
    #[error("runtime execution evidence failed: {0}")]
    Evidence(#[from] super::RuntimeExecutionEvidenceError),
    /// Portable runtime model conversion failed.
    #[error("runtime execution model failed: {0}")]
    Runtime(#[from] RuntimeModelError),
    /// Portable recovery evidence validation failed.
    #[error("runtime execution recovery failed: {0}")]
    Recovery(#[from] aos_sandbox_core::runtime_backend::ExecutionRecoveryError),
}

#[cfg(test)]
mod output_v2_tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_agent::{
        AgentFeatureSetV1, AgentFeatureV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1,
        AgentNonceV1, AgentRuntimeBindingV1, AgentSessionBindingV1, AgentSessionIdV1,
        GuestRuntimeArgumentObserveRequestV1,
    };
    use aos_sandbox_core::{
        AssignmentEpoch, DesiredGeneration, FeatureRef, IncarnationId, NamespaceGeneration,
        SandboxId,
    };
    use ed25519_dalek::SigningKey;
    use tempfile::TempDir;

    use super::*;
    use crate::journal::JournalLimits;

    fn peer() -> ProtectedAgentRoutePeerV1 {
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        ProtectedAgentRoutePeerV1::new(
            public_key,
            ObjectDigest::from_bytes([8; 32]),
            ObjectDigest::from_bytes([9; 32]),
        )
        .expect("fixed peer")
    }

    fn claim(execution: u8, requested: u64, parent: u64) -> Vec<u8> {
        let mut bytes = [0_u8; 328];
        bytes[..8].copy_from_slice(b"AOSEOR02");
        bytes[8..24].fill(execution);
        bytes[24..40].fill(3);
        for (index, start) in [40, 72, 104, 136, 168, 200, 264].into_iter().enumerate() {
            bytes[start..start + 32].fill(if start == 104 { 5 } else { index as u8 + 1 });
        }
        bytes[232..240].copy_from_slice(&requested.to_be_bytes());
        bytes[240..248].copy_from_slice(&parent.to_be_bytes());
        bytes[248..256].copy_from_slice(&requested.to_be_bytes());
        let checksum = Sha256::digest(&bytes[..296]);
        bytes[296..].copy_from_slice(&checksum);
        bytes.to_vec()
    }

    fn argument_record() -> ArgumentObservationRecordV1 {
        let runtime = AgentRuntimeBindingV1::new(
            SandboxId::from_bytes([1; 16]),
            IncarnationId::from_bytes([2; 16]),
            AssignmentEpoch::new(3),
            ObjectDigest::from_bytes([5; 32]),
            DesiredGeneration::new(4),
            NamespaceGeneration::new(5),
            [6; 16],
        )
        .expect("runtime");
        let handshake = AgentHandshakeRequestV1::new(
            AgentSessionIdV1::new([7; 16]).expect("session ID"),
            runtime.clone(),
            AgentNonceV1::new([8; 32]).expect("nonce"),
            ObjectDigest::from_bytes([8; 32]),
        )
        .expect("handshake");
        let session = AgentSessionBindingV1::derive(&handshake, &[9; 16]).expect("session");
        let response = AgentHandshakeResponseV1::new(
            session,
            [9; 16],
            AgentFeatureSetV1::new(vec![
                AgentFeatureV1::Readiness,
                AgentFeatureV1::ExecutionHandoff,
                AgentFeatureV1::RuntimeArgumentObservation,
            ])
            .expect("features"),
            [10; 64],
        )
        .expect("response");
        let request = GuestRuntimeArgumentObserveRequestV1::new(
            runtime,
            session,
            ObjectDigest::from_bytes([8; 32]),
            [11; 32],
            FeatureRef::new("aos.sandbox.runtime.linux-systemd", 1, 0).expect("profile"),
            ObjectDigest::from_bytes([12; 32]),
        )
        .expect("request");
        ArgumentObservationRecordV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([3; 16]),
            request,
            handshake,
            response,
            signed_packet_digest: None,
        }
    }

    fn cold_replay(
        requests: &[(u8, u64)],
        parent_bytes: u64,
        include_format: bool,
        include_marker: bool,
        correlation: Option<HostOutputCorrelationV1>,
    ) -> Result<(), JournalRuntimeExecutionError> {
        let directory = TempDir::new_in(std::env::current_dir().expect("current directory"))
            .expect("test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = directory.path().metadata().expect("metadata").uid();
        let binding = ObjectDigest::from_bytes([4; 32]);
        let assignment = ObjectDigest::from_bytes([5; 32]);
        let admission_state = ProtectedExecutionAdmissionStateV1 {
            authority_binding: ObjectDigest::from_bytes([6; 32]),
            resource_ledger: ObjectDigest::from_bytes([7; 32]),
        };
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "execution.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("protected journal");
        let mut store = JournalRuntimeExecutionStoreV1::initialize(
            &mut journal,
            binding,
            admission_state,
            peer(),
        )
        .expect("initialized store");
        let mut writes = Vec::new();
        if include_format {
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                OUTPUT_FORMAT_KEY.to_vec(),
                output_format_bytes(binding).to_vec(),
            ));
        }
        if include_marker {
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                OUTPUT_MARKER_KEY.to_vec(),
                marker_bytes(assignment, parent_bytes).to_vec(),
            ));
        }
        for &(execution, requested) in requests {
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                claim_key(ExecutionId::from_bytes([execution; 16])),
                claim(execution, requested, parent_bytes),
            ));
        }
        let correlation = correlation.map(|mut record| {
            record.original_journal_sequence = predicted_commit_sequence(
                store
                    .authority
                    .snapshot()
                    .expect("protected snapshot")
                    .sequence(),
                writes.len() + 1,
            )
            .expect("journal sequence");
            writes.push(JournalRecord::put(
                RecordNamespace::Effect,
                host_output_key(record.execution),
                record.encode().expect("correlation bytes").to_vec(),
            ));
            record
        });
        let transaction = JournalTransaction::new([1; 16], writes).expect("v2 transaction");
        store
            .authority
            .commit(&transaction)
            .expect("durable v2 bytes");
        drop(store);
        drop(journal);

        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "execution.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("cold reopened journal");
        let store = JournalRuntimeExecutionStoreV1::claim(&mut reopened, binding, peer())?;
        let mut observed_digests = BTreeSet::new();
        for &(execution, requested) in requests {
            let retained = store
                .load_accepted_output_v2(ExecutionId::from_bytes([execution; 16]))?
                .expect("durable provisional claim");
            assert_eq!(retained.requested_bytes, requested);
            assert_eq!(retained.stream_limits, Some((requested, 0)));
            assert_eq!(retained.create_operation, [3; 16]);
            assert_eq!(retained.assignment, assignment);
            assert_eq!(
                retained.record_digest,
                ObjectDigest::from_bytes(
                    Sha256::digest(claim(execution, requested, parent_bytes)).into()
                )
            );
            assert!(observed_digests.insert(retained.record_digest));
        }
        assert!(
            store
                .load_accepted_output_v2(ExecutionId::from_bytes([99; 16]))?
                .is_none()
        );
        if let Some(correlation) = correlation {
            let observed = store
                .query_host_output_v1(
                    correlation.execution,
                    correlation.create_operation,
                    correlation.preissue_digest,
                    correlation.claim_digest,
                    correlation.carrier_digest,
                    correlation.original_request_id,
                    correlation.assignment_digest,
                    correlation.host_boot_id,
                )?
                .expect("protected Host correlation");
            assert_eq!(
                observed.original_journal_sequence(),
                correlation.original_journal_sequence
            );
            assert_eq!(observed.claim_digest(), correlation.claim_digest);
            assert!(
                store
                    .query_host_output_v1(
                        ExecutionId::from_bytes([98; 16]),
                        correlation.create_operation,
                        correlation.preissue_digest,
                        correlation.claim_digest,
                        correlation.carrier_digest,
                        correlation.original_request_id,
                        correlation.assignment_digest,
                        correlation.host_boot_id,
                    )?
                    .is_none()
            );
            assert!(
                store
                    .query_host_output_v1(
                        correlation.execution,
                        correlation.create_operation,
                        correlation.preissue_digest,
                        correlation.claim_digest,
                        correlation.carrier_digest,
                        [99; 16],
                        correlation.assignment_digest,
                        correlation.host_boot_id,
                    )
                    .is_err()
            );
            let substitutions = [
                (
                    OperationId::from_bytes([99; 16]),
                    correlation.carrier_digest,
                    correlation.assignment_digest,
                    correlation.host_boot_id,
                ),
                (
                    correlation.create_operation,
                    ObjectDigest::from_bytes([99; 32]),
                    correlation.assignment_digest,
                    correlation.host_boot_id,
                ),
                (
                    correlation.create_operation,
                    correlation.carrier_digest,
                    ObjectDigest::from_bytes([99; 32]),
                    correlation.host_boot_id,
                ),
                (
                    correlation.create_operation,
                    correlation.carrier_digest,
                    correlation.assignment_digest,
                    [99; 16],
                ),
            ];
            for (create, carrier, assignment, boot) in substitutions {
                assert!(
                    store
                        .query_host_output_v1(
                            correlation.execution,
                            create,
                            correlation.preissue_digest,
                            correlation.claim_digest,
                            carrier,
                            correlation.original_request_id,
                            assignment,
                            boot,
                        )
                        .is_err()
                );
            }
        }
        Ok(())
    }

    #[test]
    fn cold_replay_accepts_zero_byte_provisional_claim() {
        cold_replay(&[(1, 0)], 0, true, true, None).expect("zero-byte claim survives cold replay");
    }

    #[test]
    fn cold_replay_keeps_zero_and_nonzero_execution_claims_distinct() {
        cold_replay(&[(1, 0), (2, 1)], 1, true, true, None)
            .expect("distinct claims survive one assignment ledger");
    }

    #[test]
    fn host_output_correlation_survives_cold_replay_and_rejects_foreign_attempt() {
        let correlation = HostOutputCorrelationV1 {
            execution: ExecutionId::from_bytes([1; 16]),
            create_operation: OperationId::from_bytes([3; 16]),
            preissue_digest: ObjectDigest::from_bytes([11; 32]),
            claim_digest: ObjectDigest::from_bytes(Sha256::digest(claim(1, 4, 8)).into()),
            carrier_digest: ObjectDigest::from_bytes([12; 32]),
            original_request_id: [13; 16],
            assignment_digest: ObjectDigest::from_bytes([5; 32]),
            host_boot_id: [14; 16],
            plan_digest: ObjectDigest::from_bytes([15; 32]),
            semantic_request_digest: ObjectDigest::from_bytes([16; 32]),
            deadline_boottime_nanoseconds: 17,
            original_journal_sequence: 0,
        };
        cold_replay(&[(1, 4)], 8, true, true, Some(correlation))
            .expect("atomic Host claim/correlation survives cold replay");

        let foreign_claim = HostOutputCorrelationV1 {
            claim_digest: ObjectDigest::from_bytes([99; 32]),
            ..correlation
        };
        assert!(cold_replay(&[(1, 4)], 8, true, true, Some(foreign_claim)).is_err());
    }

    #[test]
    fn cold_replay_rejects_missing_marker_and_overcommit() {
        assert!(cold_replay(&[(1, 0)], 0, true, false, None).is_err());
        assert!(cold_replay(&[(1, 8), (2, 3)], 10, true, true, None).is_err());
        assert!(cold_replay(&[(1, 0)], 0, false, true, None).is_err());
    }

    #[test]
    fn issued_or_completed_challenge_never_reenters_fresh_begin() {
        let directory = TempDir::new_in(std::env::current_dir().expect("current directory"))
            .expect("test directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private directory");
        let uid = directory.path().metadata().expect("metadata").uid();
        let binding = ObjectDigest::from_bytes([4; 32]);
        let admission_state = ProtectedExecutionAdmissionStateV1 {
            authority_binding: ObjectDigest::from_bytes([6; 32]),
            resource_ledger: ObjectDigest::from_bytes([7; 32]),
        };
        let (mut journal, _) = Journal::open_protected_at_uid(
            directory.path(),
            "execution.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("protected journal");
        let mut store = JournalRuntimeExecutionStoreV1::initialize(
            &mut journal,
            binding,
            admission_state,
            peer(),
        )
        .expect("initialized store");
        let reservation = JournalTransaction::new(
            [2; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    OUTPUT_FORMAT_KEY.to_vec(),
                    output_format_bytes(binding).to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    OUTPUT_MARKER_KEY.to_vec(),
                    marker_bytes(ObjectDigest::from_bytes([5; 32]), 0).to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    claim_key(ExecutionId::from_bytes([1; 16])),
                    claim(1, 0, 0),
                ),
            ],
        )
        .expect("reservation");
        store
            .authority
            .commit(&reservation)
            .expect("retained claim");

        let record = argument_record();
        store
            .begin_argument_observation_v1(record.clone())
            .expect("first begin");
        assert!(matches!(
            store.begin_argument_observation_v1(record.clone()),
            Err(JournalRuntimeExecutionError::RecordConflict)
        ));
        store
            .complete_argument_observation_v1(
                record.execution,
                record.create_operation,
                &record.request,
                ObjectDigest::from_bytes([13; 32]),
            )
            .expect("completion");
        assert!(matches!(
            store.begin_argument_observation_v1(record.clone()),
            Err(JournalRuntimeExecutionError::RecordConflict)
        ));

        drop(store);
        drop(journal);
        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(),
            "execution.journal",
            JournalLimits::default(),
            uid,
        )
        .expect("cold reopened journal");
        let mut store = JournalRuntimeExecutionStoreV1::claim(&mut reopened, binding, peer())
            .expect("cold replay");
        assert!(matches!(
            store.begin_argument_observation_v1(record),
            Err(JournalRuntimeExecutionError::RecordConflict)
        ));
    }
}
