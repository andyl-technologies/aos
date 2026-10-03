//! Truthful four-row decision when a completed Repair loses its public predecessor.
//!
//! Actual Storage remains held through the exact original Effect/Operation CAS
//! and same-owner ACK. Replaced Desired/current rows are observed, never written.
//! Historical codecs validate DATA and signatures; only an actual held transport
//! frame can construct the prepared decision. Physical absence is not failure.
//!
//! ```text
//! AOSORFA1 | receipt-digest[32] | sequence:u64be | completion-wall:i64be
//!          | length+Effect | length+Operation
//!          | present:u8+length+current | present:u8+length+Desired | checksum[32]
//! ```

use aos_sandbox_core::{OperationId, ProjectId};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use aos_sandbox_protocol::operator_storage_repair_terminal_v4::RepairTerminalRequestV4;
use buffa::Message as _;

use super::super::receipt::ProtectedStorageRepairReceiptVerifierV2;
use super::super::transport::HeldStorageTerminalV4;
use super::super::{CURRENT_HEAD_DOMAIN_V2, OperatorRecoveryIssuanceErrorV1,
    ProtectedOperatorRecoverySignerV1, EVIDENCE_DOMAIN, VERSION_DOMAIN, hash, take_array};
use super::successor_commit::{RepairSuccessorCommitOutcomeV1, exact_transaction_digest};
use crate::controller::{decode_recovery_current, recovery_current_key};
use crate::controller_query::CheckedSandboxResourceV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionRecordV1, PublicProjectionResourceV1, projection_key,
};
use crate::reconciler::{RepairPreconditionFailureReceiptV1, REPAIR_FAILURE_RECEIPT_BYTES,
    REPAIR_FAILURE_RECEIPT_DOMAIN, operator_repair_failure_terminal_rows_v1,
    pending_operator_repair_ledger_v1};
use crate::{Journal, JournalRecord, JournalTransaction, RecordNamespace};

const ARCHIVE_PREFIX: &[u8] = b"storage-repair-failure-predecessor-v1/";
const TERMINAL_PREFIX: &[u8] = b"storage-repair-terminal-v1/";
const ARCHIVE_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-failure-predecessor.v1\0";
const ROW_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-failure-observed-row.v1\0";
const COMMIT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-public-failure.v1\0";
const CUT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-failure-decision-cut.v1\0";

/// Retains one exact, independently validated optional public predecessor cut.
pub(in crate::controller::operator_recovery_issuance) struct ObservedRepairPreconditionV1 {
    current: Option<Vec<u8>>,
    projection: Option<Vec<u8>>,
    effect: Vec<u8>,
    operation: Vec<u8>,
    sandbox: [u8; 16],
    sequence: u64,
    replaced: bool,
}

impl ObservedRepairPreconditionV1 {
    /// Distinguishes valid replacement from malformed or unavailable authority.
    ///
    /// # Errors
    ///
    /// Rejects corrupt public rows, conflicting terminal custody or invalid admission.
    pub(in crate::controller::operator_recovery_issuance) fn capture(
        journal: &Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        operation: OperationId,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        journal.ensure_protected_authority().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        for prefix in [ARCHIVE_PREFIX, TERMINAL_PREFIX, b"storage-repair-predecessor-v1/".as_slice()] {
            if journal.get(RecordNamespace::OperatorRecovery, &key(prefix, operation)).is_some() {
                return Err(OperatorRecoveryIssuanceErrorV1::Binding);
            }
        }
        let (issued, intent) = super::issued_intent(journal, signer, operation)?;
        let pending = pending_operator_repair_ledger_v1(journal, operation,
            intent.target_id, issued.public_request_digest)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        validate_original_intent(&pending, &intent, issued.public_request_digest)?;
        let current = journal.get(RecordNamespace::OperatorRecovery,
            &recovery_current_key(intent.target_id)).map(ToOwned::to_owned);
        let projection = journal.get(RecordNamespace::DesiredState,
            &projection_key(PublicProjectionKindV1::Sandbox, intent.target_id)).map(ToOwned::to_owned);
        let replaced = validate_observed_precondition(
            current.as_deref(), projection.as_deref(), intent.target_id,
            ProjectId::from_bytes(intent.project_id), pending.request().expected_resource_version(),
            issued.current_head_digest,
        )?;
        let effect_key = effect_key(operation);
        let effect = journal.get(RecordNamespace::Effect, &effect_key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?.to_vec();
        let original = journal.get(RecordNamespace::Operation, operation.as_bytes())
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?.to_vec();
        Ok(Self {
            current, projection, effect, operation: original,
            sandbox: intent.target_id, sequence: journal.snapshot_sequence(), replaced,
        })
    }

    /// Reports replacement only after original and observed rows were validated.
    pub(in crate::controller::operator_recovery_issuance) fn is_replaced(&self) -> bool {
        self.replaced
    }

    /// Binds both explicit optional rows and the unchanged original public ledger.
    pub(in crate::controller::operator_recovery_issuance) fn predecessor_cut_at(&self, sequence: u64) -> [u8; 32] {
        hash(CUT_DOMAIN, &[&sequence.to_be_bytes(), &option_digest(self.current.as_deref()),
            &option_digest(self.projection.as_deref()), &self.effect, &self.operation])
    }

    fn matches(&self, journal: &Journal, operation: OperationId) -> bool {
        journal.get(RecordNamespace::OperatorRecovery, &recovery_current_key(self.sandbox)) == self.current.as_deref()
            && journal.get(RecordNamespace::DesiredState,
                &projection_key(PublicProjectionKindV1::Sandbox, self.sandbox)) == self.projection.as_deref()
            && journal.get(RecordNamespace::Effect, &effect_key(operation)) == Some(self.effect.as_slice())
            && journal.get(RecordNamespace::Operation, operation.as_bytes()) == Some(self.operation.as_slice())
            && journal.get(RecordNamespace::OperatorRecovery, &key(ARCHIVE_PREFIX, operation)).is_none()
            && journal.get(RecordNamespace::OperatorRecovery, &key(TERMINAL_PREFIX, operation)).is_none()
            && journal.get(RecordNamespace::OperatorRecovery,
                &key(b"storage-repair-predecessor-v1/", operation)).is_none()
    }
}

/// Contains an actual-held, immutable, exact four-row Controller transaction.
pub(in crate::controller::operator_recovery_issuance) struct PreparedRepairPreconditionFailureV1 {
    transaction: JournalTransaction,
    predecessor: ObservedRepairPreconditionV1,
    operation: OperationId,
    receipt: RepairPreconditionFailureReceiptV1,
}

impl PreparedRepairPreconditionFailureV1 {
    /// Prepares only a completed physical Repair under an actual retained hold.
    ///
    /// # Errors
    ///
    /// Rejects unchanged public predecessors, physical mismatch, invalid original
    /// custody, lost heldness, or bounded journal/receipt encoding failure.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::controller::operator_recovery_issuance) fn prepare(
        journal: &Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation: OperationId,
        body: &[u8],
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
        held: &HeldStorageTerminalV4<'_>,
        completion_wall_seconds: i64,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let predecessor = ObservedRepairPreconditionV1::capture(journal, signer, operation)?;
        if !predecessor.replaced {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let (issued, intent) = super::issued_intent(journal, signer, operation)?;
        let (proof, query, packet) = terminal_claims(journal, signer, owner, operation, body, fresh)?;
        let request = held.request();
        held.recheck(owner)?;
        if request.signed_intent() != issued.signed_intent
            || request.proof_digest() != proof
            || request.signed_header()[444..460] != query
            || request.signed_header()[460..492] != packet
            || request.owner_pair_digest() != super::terminal_owner_pair_v4(journal, signer, owner, operation)?
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let mut bytes = [0; REPAIR_FAILURE_RECEIPT_BYTES];
        bytes[..8].copy_from_slice(b"AOSORF01");
        bytes[8] = 1;
        bytes[16..32].copy_from_slice(operation.as_bytes());
        bytes[32..64].copy_from_slice(&issued.current_head_digest);
        bytes[64..96].copy_from_slice(&option_digest(predecessor.current.as_deref()));
        bytes[96..128].copy_from_slice(&option_digest(predecessor.projection.as_deref()));
        bytes[128..160].copy_from_slice(&hash(ROW_DOMAIN, &[&predecessor.effect]));
        bytes[160..192].copy_from_slice(&hash(ROW_DOMAIN, &[&predecessor.operation]));
        bytes[192..224].copy_from_slice(&issued.public_request_digest);
        bytes[224..876].copy_from_slice(request.signed_header());
        bytes[876..1084].copy_from_slice(held.witness().as_bytes());
        bytes[1084..1092].copy_from_slice(&predecessor.sequence.to_be_bytes());
        bytes[1092..1100].copy_from_slice(&completion_wall_seconds.to_be_bytes());
        let checksum = hash(REPAIR_FAILURE_RECEIPT_DOMAIN, &[&bytes[..1100]]);
        bytes[1100..].copy_from_slice(&checksum);
        let receipt = RepairPreconditionFailureReceiptV1::decode(&bytes)
            .map_err(|()| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let archive = encode_archive(&receipt, &predecessor, completion_wall_seconds)?;
        let ledger = operator_repair_failure_terminal_rows_v1(journal, operation, intent.target_id,
            issued.public_request_digest, &predecessor.operation, &predecessor.effect,
            receipt.as_bytes(), completion_wall_seconds)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let rows = Vec::from(failure_decision_rows(operation, archive, ledger, &bytes));
        let transaction = JournalTransaction::new(transaction_id(operation, receipt.as_bytes())?, rows)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        Ok(Self { transaction, predecessor, operation, receipt })
    }

    /// Reports exact durable decision or definite unchanged absence; otherwise retains ambiguity.
    ///
    /// # Errors
    ///
    /// Leaves the original hold unresolved if protected predecessor custody changes.
    pub(in crate::controller::operator_recovery_issuance) fn commit(
        &self,
        journal: &mut Journal,
    ) -> Result<RepairSuccessorCommitOutcomeV1, OperatorRecoveryIssuanceErrorV1> {
        journal.ensure_protected_authority().map_err(|_| OperatorRecoveryIssuanceErrorV1::OutcomeUnknown)?;
        if self.successor_matches(journal) {
            return Ok(RepairSuccessorCommitOutcomeV1::Replay);
        }
        if journal.snapshot_sequence() != self.predecessor.sequence
            || !self.predecessor.matches(journal, self.operation)
        {
            return Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown);
        }
        let result = journal.commit(&self.transaction);
        if journal.ensure_protected_authority().is_err() {
            return Ok(RepairSuccessorCommitOutcomeV1::Ambiguous);
        }
        if self.successor_matches(journal) {
            return Ok(RepairSuccessorCommitOutcomeV1::Committed);
        }
        if result.is_err() && journal.snapshot_sequence() == self.predecessor.sequence
            && self.predecessor.matches(journal, self.operation)
        {
            return Ok(RepairSuccessorCommitOutcomeV1::NotCommitted);
        }
        Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
    }

    /// Returns commitments to every ordered namespace, key and full value.
    ///
    /// # Errors
    ///
    /// Rejects an invalid terminal transaction frame.
    pub(in crate::controller::operator_recovery_issuance) fn settlement_commitments(
        &self,
    ) -> Result<([u8; 32], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
        Ok((exact_transaction_digest(self.transaction.id(), self.transaction.records())?, self.receipt.digest()))
    }

    fn successor_matches(&self, journal: &Journal) -> bool {
        self.transaction.records().iter().all(|row| journal.get(row.namespace(), row.key()) == row.value())
    }
}

/// Checks existing completed physical authority without requiring the old public head.
///
/// # Errors
///
/// Rejects changed original transport/admission, absent proof or physical target mismatch.
pub(in crate::controller::operator_recovery_issuance) fn terminal_claims(
    journal: &Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    owner: &ProtectedStorageRepairReceiptVerifierV2,
    operation: OperationId,
    body: &[u8],
    fresh: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<([u8; 32], [u8; 16], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
    let (issued, intent) = super::issued_intent(journal, signer, operation)?;
    let physical = super::super::receipt::verified_retained_repair_receipt_v3(journal, &intent, owner)?;
    if verify_original_transport(journal, operation, &issued, &intent)? != body {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let proof = super::read_sealed_proof_v2(journal, &issued, intent.effect_id, physical.signed_pair_digest)?;
    super::super::probe_challenge::read(journal, &issued, intent.effect_id,
        super::super::probe_challenge::ProbeStageV1::Terminal, physical.signed_pair_digest)?.matches_outcome(fresh)?;
    super::ledger_receipt::verify_fresh_physical_target(&physical, &intent, body, fresh)?;
    Ok((hash(super::PROOF_DOMAIN, &[&proof.encode()]), fresh.request().request_id(),
        hash(b"aos.sandbox.operator-repair-terminal-fresh-packet.v1\0", &[fresh.canonical_packet()])))
}

/// Independently joins a cold failure receipt, original authorization and exact four rows.
///
/// # Errors
///
/// Rejects every partial/substituted decision, signed role/history mismatch,
/// malformed archived replacement or inconsistent original public authorization.
pub(in crate::controller::operator_recovery_issuance) fn verify_current_failure_v1(
    journal: &Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    owner: &ProtectedStorageRepairReceiptVerifierV2,
    operation: OperationId,
    fresh: Option<(&[u8], &AuthenticatedBrokerMethodOutcomeV1)>,
) -> Result<([u8; 32], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
    journal.ensure_protected_authority().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if journal.get(RecordNamespace::OperatorRecovery,
        &key(b"storage-repair-predecessor-v1/", operation)).is_some()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    owner.recheck()?;
    let receipt = read_receipt(journal, signer, owner, operation)?;
    let bytes = receipt.as_bytes();
    let (issued, intent) = super::issued_intent(journal, signer, operation)?;
    let original_body = verify_original_transport(journal, operation, &issued, &intent)?;
    let physical = super::super::receipt::verified_retained_repair_receipt_v3(journal, &intent, owner)?;
    let proof = super::read_sealed_proof_v2(journal, &issued, intent.effect_id, physical.signed_pair_digest)?;
    let claims = RepairTerminalRequestV4::verify_retained_signed_header(&bytes[224..876], signer.verifier(), signer.generation())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let challenge = super::super::probe_challenge::read(journal, &issued, intent.effect_id,
        super::super::probe_challenge::ProbeStageV1::Terminal, physical.signed_pair_digest)?;
    if bytes[32..64] != issued.current_head_digest
        || bytes[192..224] != issued.public_request_digest
        || claims.signed_intent() != issued.signed_intent
        || claims.owner_pair_digest() != physical.signed_pair_digest
        || claims.proof_digest() != hash(super::PROOF_DOMAIN, &[&proof.encode()])
        || claims.signed_header()[444..460] != challenge.request_id()
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let original = super::super::bridge::verify_failure_history_custody(
        journal, operation, signer, &claims, proof.before_packet_digest,
        proof.after_packet_digest, i64::from_be_bytes(take_array(bytes, 1092)?),
        u64::from_be_bytes(take_array(bytes, 1084)?),
    )?;
    super::ledger_receipt::verify_fresh_physical_target_body(
        &physical, &intent, &original_body, original.inventory(),
    )?;
    if let Some((body, fresh)) = fresh {
        challenge.matches_outcome(fresh)?;
        let (_, _, packet) = terminal_claims(journal, signer, owner, operation, body, fresh)?;
        if claims.signed_header()[460..492] != packet {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
    }
    let archive = journal.get(RecordNamespace::OperatorRecovery, &key(ARCHIVE_PREFIX, operation))
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let predecessor = decode_archive(archive, &receipt, intent.target_id)?;
    let clock = i64::from_be_bytes(take_array(bytes, 1092)?);
    let rows = operator_repair_failure_terminal_rows_v1(journal, operation, intent.target_id,
        issued.public_request_digest, &predecessor.operation, &predecessor.effect, bytes, clock)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if !rows.iter().all(|row| journal.get(row.namespace(), row.key()) == row.value()) {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    // Revalidate the archived replacement against the unchanged admitted
    // expected version. Current Desired/head may legitimately have moved again.
    let pending = crate::reconciler::operator_repair_original_ledger_v1(
        journal, operation, intent.target_id, issued.public_request_digest,
        &predecessor.operation, &predecessor.effect,
    ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    validate_original_intent(&pending, &intent, issued.public_request_digest)?;
    if !validate_observed_precondition(predecessor.current.as_deref(), predecessor.projection.as_deref(),
        intent.target_id, ProjectId::from_bytes(intent.project_id), pending.request().expected_resource_version(), issued.current_head_digest)?
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let exact = failure_decision_rows(operation, archive.to_vec(), rows, bytes);
    signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
    owner.recheck()?;
    Ok((exact_transaction_digest(&transaction_id(operation, bytes)?, &exact)?, receipt.digest()))
}

/// Checks historical release debt against the exact original four-row decision.
///
/// # Errors
///
/// Rejects another original request cut, receipt, owner or durable decision.
pub(in crate::controller::operator_recovery_issuance) fn verify_settled_failure_receipt_v1(
    journal: &Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    owner: &ProtectedStorageRepairReceiptVerifierV2,
    operation: OperationId,
    request_cut: [u8; 32],
    expected_receipt: [u8; 32],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let receipt = read_receipt(journal, signer, owner, operation)?;
    let request = RepairTerminalRequestV4::verify_retained_signed_header(
        &receipt.as_bytes()[224..876], signer.verifier(), signer.generation(),
    ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    verify_current_failure_v1(journal, signer, owner, operation, None)?;
    if request.cut_digest() != request_cut || receipt.digest() != expected_receipt {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(())
}

fn read_receipt(
    journal: &Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    owner: &ProtectedStorageRepairReceiptVerifierV2,
    operation: OperationId,
) -> Result<RepairPreconditionFailureReceiptV1, OperatorRecoveryIssuanceErrorV1> {
    let receipt = RepairPreconditionFailureReceiptV1::decode(journal.get(
        RecordNamespace::OperatorRecovery, &key(TERMINAL_PREFIX, operation),
    ).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?)
        .map_err(|()| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if receipt.operation() != operation {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let request = RepairTerminalRequestV4::verify_retained_signed_header(
        &receipt.as_bytes()[224..876], signer.verifier(), signer.generation(),
    ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    owner.verify_terminal_witness_v4(&receipt.as_bytes()[876..1084], &request)?;
    Ok(receipt)
}

fn validate_observed_precondition(
    current: Option<&[u8]>,
    projection: Option<&[u8]>,
    sandbox: [u8; 16],
    project: ProjectId,
    expected_version: &[u8],
    issued_head: [u8; 32],
) -> Result<bool, OperatorRecoveryIssuanceErrorV1> {
    let head = current.map(decode_recovery_current).transpose()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if head.as_ref().is_some_and(|head| head.kind != 1) {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let record = projection.map(|bytes| PublicProjectionRecordV1::from_retained_record_bytes(
        PublicProjectionKindV1::Sandbox, sandbox, bytes,
    )).transpose().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let changed_projection = match record.as_ref() {
        None => true,
        Some(record) => {
            let PublicProjectionResourceV1::Sandbox(resource) = record.resource() else {
                return Err(OperatorRecoveryIssuanceErrorV1::Binding);
            };
            let checked = CheckedSandboxResourceV1::try_from(resource.clone())
                .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
            if record.project() != project || checked.sandbox_id() != sandbox
                || head.as_ref().is_some_and(|head| {
                    head.version != resource.resource_version
                        || head.desired_generation != checked.desired_generation()
                        || head.observation_sequence != checked.observation_sequence()
                })
            {
                return Err(OperatorRecoveryIssuanceErrorV1::Binding);
            }
            resource.resource_version != expected_version
        }
    };
    Ok(changed_projection || current.is_none_or(|bytes| hash(CURRENT_HEAD_DOMAIN_V2, &[bytes]) != issued_head))
}

fn validate_original_intent(
    pending: &crate::reconciler::PendingOperatorRepairLedgerV1,
    intent: &aos_sandbox_core::operator_recovery_effect::OperatorRecoveryEffectIntentV1,
    request_digest: [u8; 32],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let request = pending.request();
    let version = request.expected_resource_version();
    if intent.project_id != *pending.context().project().as_bytes()
        || intent.principal_id != *pending.context().caller().as_bytes()
        || intent.request_digest != request_digest
        || intent.target_id != request.resource_id()
        || intent.expected_version_digest != hash(VERSION_DOMAIN, &[&(version.len() as u64).to_be_bytes(), version])
        || intent.evidence_digest != hash(EVIDENCE_DOMAIN, &[&request.evidence().encode_to_vec()])
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(())
}

fn verify_original_transport(
    journal: &Journal,
    operation: OperationId,
    issued: &super::super::StorageRepairIssuanceV2,
    intent: &aos_sandbox_core::operator_recovery_effect::OperatorRecoveryEffectIntentV1,
) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
    let (body, _) = super::super::bridge::read_original_request(journal, operation)?;
    let attempt = journal.get(RecordNamespace::OperatorRecovery,
        &key(super::super::admission::ATTEMPT_PREFIX, operation))
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let admission = journal.get(RecordNamespace::OperatorRecovery,
        &key(super::super::admission::INVENTORY_PREFIX, operation))
        .filter(|bytes| bytes.len() > 16).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    if attempt[32..64] != issued.public_request_digest
        || hash(super::super::REQUEST_DOMAIN, &[&body]) != intent.effect_id
        || admission[..16] == [0; 16]
        || attempt[96..128] != hash(b"aos.sandbox.operator-repair-admission-packet.v1\0", &[&admission[16..]])
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(body)
}

fn option_digest(bytes: Option<&[u8]>) -> [u8; 32] {
    match bytes {
        None => hash(ROW_DOMAIN, &[&[0], &0_u64.to_be_bytes()]),
        Some(bytes) => hash(ROW_DOMAIN, &[&[1], &(bytes.len() as u64).to_be_bytes(), bytes]),
    }
}

fn encode_archive(
    receipt: &RepairPreconditionFailureReceiptV1,
    predecessor: &ObservedRepairPreconditionV1,
    completion_wall_seconds: i64,
) -> Result<Vec<u8>, OperatorRecoveryIssuanceErrorV1> {
    let mut bytes = b"AOSORFA1".to_vec();
    bytes.extend_from_slice(&receipt.digest());
    bytes.extend_from_slice(&predecessor.sequence.to_be_bytes());
    bytes.extend_from_slice(&completion_wall_seconds.to_be_bytes());
    for row in [&predecessor.effect, &predecessor.operation] {
        append_field(&mut bytes, row)?;
    }
    for row in [predecessor.current.as_deref(), predecessor.projection.as_deref()] {
        bytes.push(u8::from(row.is_some()));
        append_field(&mut bytes, row.unwrap_or_default())?;
    }
    bytes.extend_from_slice(&hash(ARCHIVE_DOMAIN, &[&bytes]));
    Ok(bytes)
}

fn decode_archive(
    bytes: &[u8],
    receipt: &RepairPreconditionFailureReceiptV1,
    sandbox: [u8; 16],
) -> Result<ObservedRepairPreconditionV1, OperatorRecoveryIssuanceErrorV1> {
    if bytes.len() < 56 + 18 + 32 || &bytes[..8] != b"AOSORFA1"
        || bytes[8..40] != receipt.digest()
        || bytes[40..56] != receipt.as_bytes()[1084..1100]
        || bytes[bytes.len() - 32..] != hash(ARCHIVE_DOMAIN, &[&bytes[..bytes.len() - 32]])
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let mut cursor = 56;
    let effect = take_field(bytes, &mut cursor)?;
    let operation = take_field(bytes, &mut cursor)?;
    let mut option = || -> Result<Option<&[u8]>, OperatorRecoveryIssuanceErrorV1> {
        let present = *bytes.get(cursor).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        cursor = cursor.checked_add(1).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let field = take_field(bytes, &mut cursor)?;
        match (present, field.is_empty()) {
            (0, true) => Ok(None),
            (1, false) => Ok(Some(field)),
            _ => Err(OperatorRecoveryIssuanceErrorV1::Binding),
        }
    };
    let current = option()?;
    let projection = option()?;
    if cursor != bytes.len() - 32 || effect.is_empty() || operation.is_empty()
        || receipt.as_bytes()[64..96] != option_digest(current)
        || receipt.as_bytes()[96..128] != option_digest(projection)
        || receipt.as_bytes()[128..160] != hash(ROW_DOMAIN, &[effect])
        || receipt.as_bytes()[160..192] != hash(ROW_DOMAIN, &[operation])
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    Ok(ObservedRepairPreconditionV1 {
        current: current.map(ToOwned::to_owned), projection: projection.map(ToOwned::to_owned),
        effect: effect.to_vec(), operation: operation.to_vec(), sandbox,
        sequence: u64::from_be_bytes(take_array(bytes, 40)?), replaced: true,
    })
}

fn append_field(bytes: &mut Vec<u8>, field: &[u8]) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    bytes.extend_from_slice(&u32::try_from(field.len())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?.to_be_bytes());
    bytes.extend_from_slice(field);
    Ok(())
}

fn take_field<'a>(bytes: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], OperatorRecoveryIssuanceErrorV1> {
    let start = cursor.checked_add(4).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let length = u32::from_be_bytes(bytes.get(*cursor..start)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?) as usize;
    let payload_end = bytes.len().checked_sub(32).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    let end = start.checked_add(length).filter(|end| *end <= payload_end)
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
    *cursor = end;
    bytes.get(start..end).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)
}

fn failure_decision_rows(
    operation: OperationId,
    archive: Vec<u8>,
    ledger: [JournalRecord; 2],
    receipt: &[u8],
) -> [JournalRecord; 4] {
    let [effect, public] = ledger;
    [
        JournalRecord::put(RecordNamespace::OperatorRecovery, key(ARCHIVE_PREFIX, operation), archive),
        effect,
        public,
        JournalRecord::put(RecordNamespace::OperatorRecovery, key(TERMINAL_PREFIX, operation), receipt.to_vec()),
    ]
}

fn effect_key(operation: OperationId) -> Vec<u8> {
    [operation.as_bytes().as_slice(), &0_u32.to_be_bytes()].concat()
}

fn key(prefix: &[u8], operation: OperationId) -> Vec<u8> {
    [prefix, operation.as_bytes()].concat()
}

fn transaction_id(operation: OperationId, receipt: &[u8]) -> Result<[u8; 16], OperatorRecoveryIssuanceErrorV1> {
    hash(COMMIT_DOMAIN, &[operation.as_bytes(), receipt])[..16].try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_rows_distinguish_absence_from_empty_and_every_body_change() {
        assert_ne!(option_digest(None), option_digest(Some(&[])));
        assert_ne!(option_digest(Some(b"current")), option_digest(Some(b"Current")));
    }

    #[test]
    fn nested_lengths_cannot_cross_checksum_or_overflow_frame() {
        let mut bytes = vec![0; 40];
        bytes[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(take_field(&bytes, &mut 0).is_err());
        bytes[..4].copy_from_slice(&5_u32.to_be_bytes());
        assert!(take_field(&bytes, &mut 0).is_err());
        assert!(take_field(&bytes, &mut usize::MAX).is_err());
        assert!(take_field(&[], &mut 0).is_err());
    }
}
