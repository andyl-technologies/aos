//! Durable Controller cursor for one nonauthorizing Host no-Apply settlement.
//!
//! ```text
//! AOSCSC01 | version:u16be | state:u8 | reserved:u8 |
//! execution:16 | Create-operation:16 | AOSCIA02-digest:32 |
//! AOSHNA01:384 | original-H-head:32 | signed-T-outcome:32 |
//! method42-request-id:16 | session-binding:32 | signed-request-digest:32 |
//! request-body-digest:32 | Controller-preparation-sequence:u64be |
//! observation-method:u8 | AOSCHL01-or-zero:396 |
//! signed-observation-packet-digest-or-zero:32 | SHA256(domain || preceding):32
//! ```
//!
//! The requested cursor is committed before any method-42 socket send. An
//! observed cursor joins the complete typed Host preliminary record to that
//! request and one signed method-42 or method-43 outcome. Its Controller
//! sequence and Host cut are historical coordinates, not a common held cut,
//! rollback floor, or permission to issue Floor/CAS/ACK.

use aos_proto::aos::sandbox::local::v1::{
    BrokerMethod, HostNoApplySettlementPhaseV2 as WirePhaseV2,
    QueryHostExecutionNoApplySettlementRequestV2, SettleHostExecutionNoApplyRequestV2,
    SettleHostExecutionNoApplyResponseV2,
};
use aos_sandbox_core::{ExecutionId, ObjectDigest, OperationId};
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1,
};
use aos_sandbox_protocol::host_execution_no_apply::{
    HostExecutionNoApplyRecordV1, HostNoApplySettlementPhaseV2,
    ValidatedHostNoApplySettlementRequestV2,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use crate::controller_execution_argument_attempt::ControllerExecutionArgumentAttemptV1;
use crate::runtime_execution::no_apply_settlement::{
    HostSettlementRecordV1, HostSettlementStageV1, RECORD_BYTES, validate_history,
};
use crate::{Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};

const MAGIC: &[u8; 8] = b"AOSCSC01";
const DOMAIN: &[u8] = b"aos.sandbox.controller-no-apply-settlement-cursor.v1\0";
const REQUEST_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-no-apply-settlement-request-tx.v1\0";
const OBSERVED_TRANSACTION_DOMAIN: &[u8] =
    b"aos.sandbox.controller-no-apply-settlement-observed-tx.v1\0";
const VERSION: u16 = 1;
const BYTES: usize = 8
    + 2
    + 1
    + 1
    + 16
    + 16
    + 32
    + 384
    + 32
    + 32
    + 16
    + 32
    + 32
    + 32
    + 8
    + 1
    + RECORD_BYTES
    + 32
    + 32;

/// Reports conflicting or ambiguous protected Controller settlement custody.
#[derive(Debug, thiserror::Error)]
pub enum ControllerNoApplySettlementCursorErrorV1 {
    /// The source, signed request, Host stage, or stored cursor is not exact.
    #[error("Controller no-Apply settlement cursor is not current")]
    NotCurrent,
    /// A different signed request already owns this execution.
    #[error("execution already has a different no-Apply settlement cursor")]
    Conflict,
    /// A protected append may have committed and requires cold readback.
    #[error("Controller no-Apply settlement cursor append is ambiguous")]
    OutcomeUnknown,
    /// The Controller journal has no protected writer authority.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Distinguishes a durably requested stage from a signed historical observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControllerNoApplyCursorStateV1 {
    /// The original signed method-42 request is retained but no Host stage is known.
    Requested,
    /// A signed method-42 result or method-43 query reported the exact stage.
    Observed,
}

/// Carries historical coordinates for a future held two-owner cut.
///
/// These values are not an anti-rollback floor. In particular the Controller
/// sequence was recorded before the Host stage, and neither owner claim is
/// held by this value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalControllerHostNoApplyCutV1 {
    /// Protected Controller sequence before its cursor append.
    pub controller_preparation_sequence: u64,
    /// Host protected-journal sequence before its preliminary append.
    pub host_epoch: u64,
    /// Host digest-bearing Effect cut at that epoch.
    pub host_pre_lease_cut: ObjectDigest,
    /// Exact preliminary Host record head.
    pub host_preliminary_head: ObjectDigest,
}

/// Retains one exact signed request and its nonauthorizing Host observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControllerNoApplySettlementCursorV1 {
    execution: ExecutionId,
    operation: OperationId,
    source_digest: ObjectDigest,
    marker: HostExecutionNoApplyRecordV1,
    archive_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
    request_id: [u8; 16],
    session_binding: [u8; 32],
    signed_request_digest: [u8; 32],
    request_body_digest: ObjectDigest,
    controller_preparation_sequence: u64,
    observation_method: u8,
    preliminary: Option<[u8; RECORD_BYTES]>,
    signed_observation_digest: Option<ObjectDigest>,
}

impl ControllerNoApplySettlementCursorV1 {
    /// Returns whether a signed Host stage has been retained.
    #[must_use]
    pub const fn state(self) -> ControllerNoApplyCursorStateV1 {
        if self.preliminary.is_some() {
            ControllerNoApplyCursorStateV1::Observed
        } else {
            ControllerNoApplyCursorStateV1::Requested
        }
    }

    /// Returns the exact protected Controller journal sequence before request reservation.
    #[must_use]
    pub const fn controller_preparation_sequence(self) -> u64 {
        self.controller_preparation_sequence
    }

    /// Returns the canonical Host preliminary record, if signed evidence exists.
    #[must_use]
    pub const fn preliminary(self) -> Option<[u8; RECORD_BYTES]> {
        self.preliminary
    }

    /// Extracts only historical Controller and Host cut coordinates.
    #[must_use]
    pub fn historical_cut(self) -> Option<HistoricalControllerHostNoApplyCutV1> {
        let stage = HostSettlementRecordV1::decode_canonical(&self.preliminary?).ok()?;
        Some(HistoricalControllerHostNoApplyCutV1 {
            controller_preparation_sequence: self.controller_preparation_sequence,
            host_epoch: stage.epoch,
            host_pre_lease_cut: stage.pre_lease_cut,
            host_preliminary_head: stage.digest(),
        })
    }

    /// Constructs a request cursor only from an authenticated signed method-42 request.
    ///
    /// # Errors
    ///
    /// Rejects a foreign source, marker, H/T coordinate, request, or challenge.
    pub fn from_signed_preliminary_request(
        source: &ControllerExecutionArgumentAttemptV1,
        marker: HostExecutionNoApplyRecordV1,
        archive_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
        signed_request: &AuthenticatedBrokerMethodRequestV1,
        validated: &ValidatedHostNoApplySettlementRequestV2,
    ) -> Result<Self, ControllerNoApplySettlementCursorErrorV1> {
        let original = validated.original();
        let fields = marker.fields();
        let body = SettleHostExecutionNoApplyRequestV2::decode_from_slice(
            signed_request.exact_body(),
        )
        .map_err(|_| ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
        let header = body
            .header
            .as_option()
            .ok_or(ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
        if signed_request.method() != BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            || signed_request.authorization().is_some()
            || !body.__buffa_unknown_fields.is_empty()
            || body.encode_to_vec() != signed_request.exact_body()
            || header.request_id.as_slice() != signed_request.request_id().as_slice()
            || header.deadline_boottime_nanoseconds
                != signed_request.deadline_boottime_nanoseconds()
            || header.maximum_response_bytes != signed_request.maximum_response_bytes()
            || header.protocol_major != u32::from(validated.header().protocol_version().major())
            || header.protocol_minor != u32::from(validated.header().protocol_version().minor())
            || header.audience.as_known() != Some(validated.header().audience())
            || body.canonical_attempt.as_slice() != source.canonical_bytes().as_slice()
            || body.original_session_binding.as_slice()
                != fields.original_session_binding.as_slice()
            || body.original_signed_request_digest.as_slice()
                != fields.original_signed_request_digest.as_slice()
            || body.archive_head.as_slice() != archive_head.as_bytes()
            || body.signed_terminal_outcome.as_slice() != signed_terminal_outcome.as_bytes()
            || body.phase.as_known()
                != Some(WirePhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_PRELIMINARY)
            || !body.canonical_controller_coordinate.is_empty()
            || body.challenge.as_slice() != signed_request.request_id().as_slice()
            || validated.phase() != HostNoApplySettlementPhaseV2::Preliminary
            || *validated.header().request_id() != signed_request.request_id()
            || validated.challenge() != signed_request.request_id()
            || original.canonical_attempt() != &source.canonical_bytes()
            || original.original_request_id() != source.request_id()
            || original.original_session_binding() != fields.original_session_binding
            || original.original_signed_request_digest() != fields.original_signed_request_digest
            || validated.archive_head() != archive_head
            || validated.signed_terminal_outcome() != signed_terminal_outcome
            || fields.execution_id != *source.execution().as_bytes()
            || fields.create_operation_id != *source.create_operation().as_bytes()
            || fields.original_request_id != source.request_id()
            || fields.source_record_digest != *source.record_digest().as_bytes()
            || fields.assignment_digest != *source.assignment_digest().as_bytes()
            || fields.host_boot_id != source.host_boot_id()
            || signed_request.request_id() == fields.terminal_request_id
            || signed_request.session_binding() == [0; 32]
            || signed_request.signed_request_digest() == [0; 32]
            || archive_head.as_bytes() == &[0; 32]
            || signed_terminal_outcome.as_bytes() == &[0; 32]
        {
            return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
        }
        Ok(Self {
            execution: source.execution(),
            operation: source.create_operation(),
            source_digest: source.record_digest(),
            marker,
            archive_head,
            signed_terminal_outcome,
            request_id: signed_request.request_id(),
            session_binding: signed_request.session_binding(),
            signed_request_digest: signed_request.signed_request_digest(),
            request_body_digest: digest_body(signed_request.exact_body()),
            controller_preparation_sequence: 0,
            observation_method: 0,
            preliminary: None,
            signed_observation_digest: None,
        })
    }

    fn matches_archive(
        self,
        source: &ControllerExecutionArgumentAttemptV1,
        marker: HostExecutionNoApplyRecordV1,
        archive_head: ObjectDigest,
        signed_terminal_outcome: ObjectDigest,
    ) -> bool {
        self.execution == source.execution()
            && self.operation == source.create_operation()
            && self.source_digest == source.record_digest()
            && self.marker == marker
            && self.archive_head == archive_head
            && self.signed_terminal_outcome == signed_terminal_outcome
    }

    fn matches_preliminary(self, bytes: &[u8]) -> bool {
        let Ok(stage) = HostSettlementRecordV1::decode_canonical(bytes) else {
            return false;
        };
        stage.stage == HostSettlementStageV1::Preliminary
            && stage.matches_preliminary_source(
                self.marker,
                stage.handoff_digest,
                self.archive_head,
                self.signed_terminal_outcome,
                self.session_binding,
                self.request_id,
            )
            && validate_history(self.marker, Some(stage), None, None, stage.commit_sequence)
                == Ok(Some(HostSettlementStageV1::Preliminary))
    }

    fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_be_bytes());
        bytes.push(match self.state() {
            ControllerNoApplyCursorStateV1::Requested => 1,
            ControllerNoApplyCursorStateV1::Observed => 2,
        });
        bytes.push(0);
        bytes.extend_from_slice(self.execution.as_bytes());
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(self.source_digest.as_bytes());
        bytes.extend_from_slice(&self.marker.encode_canonical());
        bytes.extend_from_slice(self.archive_head.as_bytes());
        bytes.extend_from_slice(self.signed_terminal_outcome.as_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.extend_from_slice(&self.session_binding);
        bytes.extend_from_slice(&self.signed_request_digest);
        bytes.extend_from_slice(self.request_body_digest.as_bytes());
        bytes.extend_from_slice(&self.controller_preparation_sequence.to_be_bytes());
        bytes.push(self.observation_method);
        bytes.extend_from_slice(&self.preliminary.unwrap_or([0; RECORD_BYTES]));
        bytes.extend_from_slice(
            self.signed_observation_digest
                .map_or([0; 32], |digest| *digest.as_bytes())
                .as_slice(),
        );
        bytes.extend_from_slice(
            &Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes)
                .finalize(),
        );
        bytes
    }

    fn decode(key: &[u8], bytes: &[u8]) -> Result<Self, ControllerNoApplySettlementCursorErrorV1> {
        if key.len() != 16
            || bytes.len() != BYTES
            || bytes.get(..8) != Some(MAGIC.as_slice())
            || bytes[8..10] != VERSION.to_be_bytes()
            || bytes[11] != 0
            || Sha256::new()
                .chain_update(DOMAIN)
                .chain_update(&bytes[..BYTES - 32])
                .finalize()
                .as_slice()
                != &bytes[BYTES - 32..]
        {
            return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
        }
        let mut reader = Reader { bytes, offset: 12 };
        let execution = ExecutionId::from_bytes(reader.take()?);
        let operation = OperationId::from_bytes(reader.take()?);
        let source_digest = reader.digest()?;
        let marker = HostExecutionNoApplyRecordV1::decode_canonical(&reader.take::<384>()?)
            .map_err(|_| ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
        let archive_head = reader.digest()?;
        let signed_terminal_outcome = reader.digest()?;
        let request_id = reader.take()?;
        let session_binding = reader.take()?;
        let signed_request_digest = reader.take()?;
        let request_body_digest = reader.digest()?;
        let controller_preparation_sequence = u64::from_be_bytes(reader.take()?);
        let observation_method = reader.take::<1>()?[0];
        let stage = reader.take::<RECORD_BYTES>()?;
        let signed_observation = reader.take::<32>()?;
        let (preliminary, signed_observation_digest) = match bytes[10] {
            1 if observation_method == 0
                && stage == [0; RECORD_BYTES]
                && signed_observation == [0; 32] =>
            {
                (None, None)
            }
            2 if matches!(observation_method, 42 | 43) && signed_observation != [0; 32] => (
                Some(stage),
                Some(ObjectDigest::from_bytes(signed_observation)),
            ),
            _ => return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent),
        };
        let cursor = Self {
            execution,
            operation,
            source_digest,
            marker,
            archive_head,
            signed_terminal_outcome,
            request_id,
            session_binding,
            signed_request_digest,
            request_body_digest,
            controller_preparation_sequence,
            observation_method,
            preliminary,
            signed_observation_digest,
        };
        if reader.offset != BYTES - 32
            || execution.as_bytes() != key
            || marker.fields().execution_id != *execution.as_bytes()
            || marker.fields().create_operation_id != *operation.as_bytes()
            || marker.fields().source_record_digest != *source_digest.as_bytes()
            || source_digest.as_bytes() == &[0; 32]
            || request_id == [0; 16]
            || request_id == marker.fields().original_request_id
            || request_id == marker.fields().terminal_request_id
            || session_binding == [0; 32]
            || signed_request_digest == [0; 32]
            || controller_preparation_sequence == 0
            || cursor
                .preliminary
                .is_some_and(|record| !cursor.matches_preliminary(&record))
        {
            return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
        }
        Ok(cursor)
    }
}

/// Reads the exact protected cursor without reviving a Host lease.
///
/// Callers must independently recheck the Controller source and signed H/T
/// archive around this readback. The journal sequence is a coordinate only.
///
/// # Errors
///
/// Rejects unprotected, corrupt, or foreign Controller custody.
pub fn read_controller_no_apply_settlement_cursor_v1(
    controller: &Journal,
    source: &ControllerExecutionArgumentAttemptV1,
    marker: HostExecutionNoApplyRecordV1,
    archive_head: ObjectDigest,
    signed_terminal_outcome: ObjectDigest,
) -> Result<Option<ControllerNoApplySettlementCursorV1>, ControllerNoApplySettlementCursorErrorV1> {
    controller.ensure_protected_authority()?;
    if controller.get(
        RecordNamespace::ControllerExecutionArgumentAttempt,
        source.execution().as_bytes(),
    ) != Some(source.canonical_bytes().as_slice())
    {
        return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
    }
    let Some(bytes) = controller.get(
        RecordNamespace::ControllerNoApplySettlementCursor,
        source.execution().as_bytes(),
    ) else {
        return Ok(None);
    };
    let cursor = ControllerNoApplySettlementCursorV1::decode(source.execution().as_bytes(), bytes)?;
    if !cursor.matches_archive(source, marker, archive_head, signed_terminal_outcome)
        || cursor.controller_preparation_sequence >= controller.snapshot_sequence()
    {
        return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
    }
    Ok(Some(cursor))
}

/// Validates every protected cursor before Controller ledger replay proceeds.
///
/// This checks canonical local custody and the original Controller source; it
/// cannot replace the signed Host archive/currentness readback or a held
/// cross-owner rollback floor.
///
/// # Errors
///
/// Rejects an orphaned, corrupt, or foreign cursor or an unprotected journal.
pub fn validate_all_controller_no_apply_cursors_v1(
    controller: &Journal,
) -> Result<(), ControllerNoApplySettlementCursorErrorV1> {
    if controller
        .records(RecordNamespace::ControllerNoApplySettlementCursor)
        .next()
        .is_none()
    {
        return Ok(());
    }
    controller.ensure_protected_authority()?;
    for (key, bytes) in controller.records(RecordNamespace::ControllerNoApplySettlementCursor) {
        let cursor = ControllerNoApplySettlementCursorV1::decode(key, bytes)?;
        let source_bytes = controller
            .get(RecordNamespace::ControllerExecutionArgumentAttempt, key)
            .ok_or(ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
        let source = ControllerExecutionArgumentAttemptV1::decode_canonical(source_bytes)
            .map_err(|_| ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
        if !cursor.matches_archive(
            &source,
            cursor.marker,
            cursor.archive_head,
            cursor.signed_terminal_outcome,
        ) || cursor.controller_preparation_sequence >= controller.snapshot_sequence()
        {
            return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
        }
    }
    Ok(())
}

/// Durably reserves one signed method-42 identity before its socket send.
///
/// # Errors
///
/// Rejects an existing foreign cursor or ambiguous protected append. A caller
/// must retain the prepared broker request but must not send on any error.
pub fn reserve_controller_no_apply_settlement_cursor_v1(
    controller: &mut Journal,
    source: &ControllerExecutionArgumentAttemptV1,
    mut candidate: ControllerNoApplySettlementCursorV1,
) -> Result<ControllerNoApplySettlementCursorV1, ControllerNoApplySettlementCursorErrorV1> {
    controller.ensure_protected_authority()?;
    if !candidate.matches_archive(
        source,
        candidate.marker,
        candidate.archive_head,
        candidate.signed_terminal_outcome,
    ) {
        return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
    }
    if let Some(existing) = read_controller_no_apply_settlement_cursor_v1(
        controller,
        source,
        candidate.marker,
        candidate.archive_head,
        candidate.signed_terminal_outcome,
    )? {
        candidate.controller_preparation_sequence = existing.controller_preparation_sequence;
        return if existing == candidate {
            Ok(existing)
        } else {
            Err(ControllerNoApplySettlementCursorErrorV1::Conflict)
        };
    }
    candidate.controller_preparation_sequence = controller.snapshot_sequence();
    commit_cursor(controller, candidate, REQUEST_TRANSACTION_DOMAIN)?;
    read_exact_cursor(controller, candidate)
}

/// Retains one signed historical preliminary observation under the cursor.
///
/// Method 43 may close a crash window left by method 42, but never authorizes
/// the Controller floor or a failed-Create CAS. A changed observation remains
/// a conflict even when a later signed query reports it.
///
/// # Errors
///
/// Rejects a foreign signed packet, stage, source, or ambiguous append.
pub fn observe_controller_no_apply_preliminary_v1(
    controller: &mut Journal,
    source: &ControllerExecutionArgumentAttemptV1,
    cursor: ControllerNoApplySettlementCursorV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    preliminary: &[u8],
) -> Result<ControllerNoApplySettlementCursorV1, ControllerNoApplySettlementCursorErrorV1> {
    let current = read_controller_no_apply_settlement_cursor_v1(
        controller,
        source,
        cursor.marker,
        cursor.archive_head,
        cursor.signed_terminal_outcome,
    )?
    .ok_or(ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
    if current != cursor || !cursor.matches_preliminary(preliminary) {
        return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
    }
    if outcome.request().authorization().is_some() {
        return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
    }
    let observation_method = match outcome.method() {
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2
            if outcome.request().request_id() == cursor.request_id
                && outcome.request().session_binding() == cursor.session_binding
                && outcome.request().signed_request_digest() == cursor.signed_request_digest
                && digest_body(outcome.request().exact_body()) == cursor.request_body_digest
                && direct_response_matches(outcome, preliminary) =>
        {
            42
        }
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2
            if cold_response_matches(outcome, source, cursor, preliminary) =>
        {
            43
        }
        _ => return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent),
    };
    let signed_observation_digest =
        ObjectDigest::from_bytes(Sha256::digest(outcome.canonical_packet()).into());
    if let Some(existing) = current.preliminary {
        return if existing.as_slice() == preliminary {
            Ok(current)
        } else {
            Err(ControllerNoApplySettlementCursorErrorV1::Conflict)
        };
    }
    let mut observed = cursor;
    observed.observation_method = observation_method;
    observed.preliminary = Some(
        preliminary
            .try_into()
            .map_err(|_| ControllerNoApplySettlementCursorErrorV1::NotCurrent)?,
    );
    observed.signed_observation_digest = Some(signed_observation_digest);
    commit_cursor(controller, observed, OBSERVED_TRANSACTION_DOMAIN)?;
    read_exact_cursor(controller, observed)
}

fn direct_response_matches(outcome: &AuthenticatedBrokerMethodOutcomeV1, stage: &[u8]) -> bool {
    let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = outcome.result() else {
        return false;
    };
    let Ok(response) = SettleHostExecutionNoApplyResponseV2::decode_from_slice(exact_body) else {
        return false;
    };
    response.__buffa_unknown_fields.is_empty()
        && response.encode_to_vec() == *exact_body
        && response.canonical_record == stage
}

fn cold_response_matches(
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
    source: &ControllerExecutionArgumentAttemptV1,
    cursor: ControllerNoApplySettlementCursorV1,
    stage: &[u8],
) -> bool {
    let Ok(query) = QueryHostExecutionNoApplySettlementRequestV2::decode_from_slice(
        outcome.request().exact_body(),
    ) else {
        return false;
    };
    let Some(header) = query.header.as_option() else {
        return false;
    };
    if !query.__buffa_unknown_fields.is_empty()
        || query.encode_to_vec() != outcome.request().exact_body()
        || header.request_id.as_slice() != outcome.request().request_id().as_slice()
        || header.deadline_boottime_nanoseconds
            != outcome.request().deadline_boottime_nanoseconds()
        || header.maximum_response_bytes != outcome.request().maximum_response_bytes()
        || query.canonical_attempt != source.canonical_bytes()
        || query.original_session_binding != cursor.marker.fields().original_session_binding
        || query.original_signed_request_digest
            != cursor.marker.fields().original_signed_request_digest
    {
        return false;
    }
    outcome
        .recorded_host_no_apply_settlement_history()
        .ok()
        .flatten()
        .and_then(|history| history.stages()[0])
        .is_some_and(|record| record.as_slice() == stage)
}

fn read_exact_cursor(
    controller: &Journal,
    expected: ControllerNoApplySettlementCursorV1,
) -> Result<ControllerNoApplySettlementCursorV1, ControllerNoApplySettlementCursorErrorV1> {
    let bytes = controller
        .get(
            RecordNamespace::ControllerNoApplySettlementCursor,
            expected.execution.as_bytes(),
        )
        .ok_or(ControllerNoApplySettlementCursorErrorV1::OutcomeUnknown)?;
    let readback =
        ControllerNoApplySettlementCursorV1::decode(expected.execution.as_bytes(), bytes)?;
    if readback != expected {
        return Err(ControllerNoApplySettlementCursorErrorV1::OutcomeUnknown);
    }
    Ok(readback)
}

fn commit_cursor(
    controller: &mut Journal,
    cursor: ControllerNoApplySettlementCursorV1,
    domain: &[u8],
) -> Result<(), ControllerNoApplySettlementCursorErrorV1> {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(domain)
        .chain_update(cursor.execution.as_bytes())
        .chain_update(cursor.request_id)
        .finalize()
        .into();
    let transaction_id = digest[..16]
        .try_into()
        .map_err(|_| ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
    let transaction = JournalTransaction::new(
        transaction_id,
        vec![JournalRecord::put(
            RecordNamespace::ControllerNoApplySettlementCursor,
            cursor.execution.as_bytes().to_vec(),
            cursor.encode(),
        )],
    )?;
    controller
        .commit(&transaction)
        .map_err(|_| ControllerNoApplySettlementCursorErrorV1::OutcomeUnknown)?;
    Ok(())
}

fn digest_body(body: &[u8]) -> ObjectDigest {
    ObjectDigest::from_bytes(Sha256::digest(body).into())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take<const N: usize>(
        &mut self,
    ) -> Result<[u8; N], ControllerNoApplySettlementCursorErrorV1> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ControllerNoApplySettlementCursorErrorV1::NotCurrent)?
            .try_into()
            .map_err(|_| ControllerNoApplySettlementCursorErrorV1::NotCurrent)?;
        self.offset = end;
        Ok(value)
    }

    fn digest(&mut self) -> Result<ObjectDigest, ControllerNoApplySettlementCursorErrorV1> {
        let bytes = self.take::<32>()?;
        if bytes == [0; 32] {
            return Err(ControllerNoApplySettlementCursorErrorV1::NotCurrent);
        }
        Ok(ObjectDigest::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use aos_sandbox_protocol::host_execution_no_apply::HostExecutionNoApplyRecordFieldsV1;

    use crate::JournalLimits;
    use crate::runtime_execution::no_apply_settlement::{
        ControllerAssertedSettlementArchivesV1, HostObservedSettlementIdentityV1,
    };

    use super::*;

    fn source() -> ControllerExecutionArgumentAttemptV1 {
        let mut bytes = [0; 336];
        bytes[..8].copy_from_slice(b"AOSCIA02");
        bytes[8..24].fill(1);
        bytes[24..40].fill(2);
        bytes[40..56].fill(3);
        for (start, value) in [(56, 4), (88, 5), (120, 6), (152, 7), (184, 8), (216, 9)] {
            bytes[start..start + 32].fill(value);
        }
        bytes[248..264].fill(10);
        bytes[264..296].fill(11);
        bytes[296..304].copy_from_slice(&42_u64.to_be_bytes());
        let digest = Sha256::new()
            .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
            .chain_update(&bytes[..304])
            .finalize();
        bytes[304..].copy_from_slice(&digest);
        ControllerExecutionArgumentAttemptV1::decode_canonical(&bytes).unwrap()
    }

    fn marker(source: &ControllerExecutionArgumentAttemptV1) -> HostExecutionNoApplyRecordV1 {
        HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
            execution_id: *source.execution().as_bytes(),
            create_operation_id: *source.create_operation().as_bytes(),
            original_request_id: source.request_id(),
            terminal_request_id: [4; 16],
            host_boot_id: source.host_boot_id(),
            assignment_digest: *source.assignment_digest().as_bytes(),
            source_record_digest: *source.record_digest().as_bytes(),
            original_session_binding: [8; 32],
            original_signed_request_digest: [9; 32],
            terminal_session_binding: [10; 32],
            terminal_signed_request_digest: [11; 32],
            runtime_handle: [12; 32],
            execution_store_binding: [13; 32],
            commit_sequence: 10,
        })
        .unwrap()
    }

    fn cursor(source: &ControllerExecutionArgumentAttemptV1) -> ControllerNoApplySettlementCursorV1 {
        ControllerNoApplySettlementCursorV1 {
            execution: source.execution(),
            operation: source.create_operation(),
            source_digest: source.record_digest(),
            marker: marker(source),
            archive_head: ObjectDigest::from_bytes([14; 32]),
            signed_terminal_outcome: ObjectDigest::from_bytes([15; 32]),
            request_id: [16; 16],
            session_binding: [17; 32],
            signed_request_digest: [18; 32],
            request_body_digest: ObjectDigest::from_bytes([19; 32]),
            controller_preparation_sequence: 0,
            observation_method: 0,
            preliminary: None,
            signed_observation_digest: None,
        }
    }

    fn preliminary(cursor: ControllerNoApplySettlementCursorV1) -> [u8; RECORD_BYTES] {
        let observed = HostObservedSettlementIdentityV1::from_marker_and_handoff(
            cursor.marker,
            ObjectDigest::from_bytes([20; 32]),
        )
        .unwrap();
        let archives = ControllerAssertedSettlementArchivesV1::new(
            cursor.archive_head,
            cursor.signed_terminal_outcome,
        )
        .unwrap();
        HostSettlementRecordV1::preliminary(
            observed,
            archives,
            11,
            ObjectDigest::from_bytes([21; 32]),
            cursor.session_binding,
            cursor.request_id,
            13,
        )
        .unwrap()
        .encode_canonical()
    }

    #[test]
    fn typed_cursor_rejects_foreign_stage_and_corrupt_record() {
        let source = source();
        let mut cursor = cursor(&source);
        cursor.controller_preparation_sequence = 20;
        let stage = preliminary(cursor);

        assert!(cursor.matches_preliminary(&stage));
        for offset in [12, 28, 44, 108, 140, 212, 244] {
            let mut changed = HostSettlementRecordV1::decode_canonical(&stage).unwrap();
            match offset {
                12 => changed.execution = ExecutionId::from_bytes([22; 16]),
                28 => changed.operation = OperationId::from_bytes([22; 16]),
                44 => changed.marker_digest = ObjectDigest::from_bytes([22; 32]),
                108 => changed.archives.original_h_head = ObjectDigest::from_bytes([22; 32]),
                140 => changed.archives.signed_terminal_outcome = ObjectDigest::from_bytes([22; 32]),
                212 => changed.session_binding = [22; 32],
                244 => changed.challenge = [22; 16],
                _ => unreachable!(),
            }
            assert!(!cursor.matches_preliminary(&changed.encode_canonical()));
        }

        cursor.preliminary = Some(stage);
        cursor.observation_method = 42;
        cursor.signed_observation_digest = Some(ObjectDigest::from_bytes([23; 32]));
        let historical_cut = cursor.historical_cut().unwrap();
        assert_eq!(historical_cut.controller_preparation_sequence, 20);
        assert_eq!(historical_cut.host_epoch, 11);
        assert_eq!(historical_cut.host_pre_lease_cut, ObjectDigest::from_bytes([21; 32]));
        let canonical = cursor.encode();
        assert_eq!(canonical.len(), BYTES);
        assert_eq!(ControllerNoApplySettlementCursorV1::decode(source.execution().as_bytes(), &canonical).unwrap(), cursor);
        for offset in [0, 10, 12, 44, 76, 460, 524, 540, 644, 645, BYTES - 1] {
            let mut changed = canonical.clone();
            changed[offset] ^= 1;
            assert!(ControllerNoApplySettlementCursorV1::decode(source.execution().as_bytes(), &changed).is_err());
        }
        assert!(ControllerNoApplySettlementCursorV1::decode([24; 16].as_slice(), &canonical).is_err());
    }

    #[test]
    fn protected_cursor_reservation_is_exact_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let (mut controller, _) = Journal::open_protected_at_uid(
            directory.path(), "controller.journal", JournalLimits::default(), uid,
        ).unwrap();
        let source = source();
        let original = JournalTransaction::new(
            [30; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerExecutionArgumentAttempt,
                source.execution().as_bytes().to_vec(),
                source.canonical_bytes().to_vec(),
            )],
        ).unwrap();
        controller.commit(&original).unwrap();
        let candidate = cursor(&source);

        assert!(read_controller_no_apply_settlement_cursor_v1(
            &controller, &source, candidate.marker, candidate.archive_head,
            candidate.signed_terminal_outcome,
        ).unwrap().is_none());
        let retained = reserve_controller_no_apply_settlement_cursor_v1(&mut controller, &source, candidate).unwrap();
        assert!(retained.controller_preparation_sequence() > 0);
        assert_eq!(reserve_controller_no_apply_settlement_cursor_v1(&mut controller, &source, candidate).unwrap(), retained);
        let mut foreign = candidate;
        foreign.request_id = [25; 16];
        assert!(matches!(
            reserve_controller_no_apply_settlement_cursor_v1(&mut controller, &source, foreign),
            Err(ControllerNoApplySettlementCursorErrorV1::Conflict)
        ));
        drop(controller);

        let (mut reopened, _) = Journal::open_protected_at_uid(
            directory.path(), "controller.journal", JournalLimits::default(), uid,
        ).unwrap();
        assert_eq!(read_controller_no_apply_settlement_cursor_v1(
            &reopened, &source, retained.marker, retained.archive_head,
            retained.signed_terminal_outcome,
        ).unwrap(), Some(retained));
        assert!(read_controller_no_apply_settlement_cursor_v1(
            &reopened, &source, retained.marker,
            ObjectDigest::from_bytes([26; 32]), retained.signed_terminal_outcome,
        ).is_err());
        validate_all_controller_no_apply_cursors_v1(&reopened).unwrap();

        let mut corrupt = retained.encode();
        corrupt[76] ^= 1;
        let replacement = JournalTransaction::new(
            [31; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerNoApplySettlementCursor,
                source.execution().as_bytes().to_vec(),
                corrupt,
            )],
        ).unwrap();
        reopened.commit(&replacement).unwrap();
        assert!(validate_all_controller_no_apply_cursors_v1(&reopened).is_err());
    }
}
