//! Closed atomic Controller successor for a physically proved Storage Repair.
//!
//! The journal transaction advances an already accepted public Effect and
//! Operation with the exact predecessor archive, terminal receipt, desired
//! Sandbox projection, and protected recovery head. Storage remains a separate
//! owner: the Repair-specific caller retains its actual same-socket currentness
//! fence through the CAS and owner settlement. Public activation remains closed.

use aos_sandbox_core::{OperationId, ProjectId};
use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodOutcomeV1;
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::super::receipt::ProtectedStorageRepairReceiptVerifierV2;
use super::super::{
    CURRENT_HEAD_DOMAIN_V2, EVIDENCE_DOMAIN, OperatorRecoveryIssuanceErrorV1,
    ProtectedOperatorRecoverySignerV1, VERSION_DOMAIN, hash,
};
use super::issued_intent;
use super::ledger_receipt::BoundRepairLedgerReceiptV1;
use super::held_receipt::{HeldRepairLedgerReceiptV2, exact_predecessor_archive};
use super::super::transport::HeldStorageTerminalV4;
use crate::controller::{operator_repair_successor_current_v1, recovery_current_key};
use crate::controller_query::CheckedSandboxResourceV1;
use crate::controller_service::public_projection::{
    PublicProjectionKindV1, PublicProjectionResourceV1, PublicProjectionStoreV1, PublicProjectionRecordV1,
};
use crate::production_operation_compiler::repair_sandbox_successor_projection_v1;
use crate::reconciler::pending_operator_repair_ledger_v1;
use crate::{EffectReceipt, Journal, JournalRecord, JournalTransaction, RecordNamespace};

const TERMINAL_RECEIPT_PREFIX: &[u8] = b"storage-repair-terminal-v1/";
const COMMIT_DOMAIN: &[u8] = b"aos.sandbox.operator-repair-public-successor.v1\0";

/// Reports the outcome of an exact local terminal CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::controller::operator_recovery_issuance) enum RepairSuccessorCommitOutcomeV1 {
    /// All successor records were made durable by this call.
    Committed,
    /// The exact successor was already durable.
    Replay,
    /// Persistence failed without a provable complete successor.
    Ambiguous,
    /// Exact protected predecessor remains and every successor row is absent.
    NotCommitted,
}

/// Holds one fully prepared, still-closed terminal transaction.
#[allow(dead_code, reason = "public operator Repair route remains closed")]
pub(in crate::controller::operator_recovery_issuance) struct PreparedRepairSuccessorV1 {
    transaction: JournalTransaction,
    predecessor_sequence: u64,
    predecessor_current: Vec<u8>,
    predecessor_projection: Vec<u8>,
    predecessor_effect: Vec<u8>,
    predecessor_operation: Vec<u8>,
}

#[allow(dead_code, reason = "public operator Repair route remains closed")]
impl PreparedRepairSuccessorV1 {
    pub(in crate::controller::operator_recovery_issuance) fn terminal_claims(&self) -> Result<([u8; 32], [u8; 16], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
        let receipt = BoundRepairLedgerReceiptV1::decode(self.transaction.records()[5].value()
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?)?;
        Ok((receipt.proof_digest, receipt.fresh_request_id, receipt.fresh_packet_digest))
    }

    pub(in crate::controller::operator_recovery_issuance) fn settlement_commitments(
        &self,
    ) -> Result<([u8; 32], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
        let receipt = self.transaction.records()[5]
            .value()
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;

        Ok((
            exact_transaction_digest(self.transaction.id(), self.transaction.records())?,
            hash(b"aos.sandbox.operator-repair-held-ledger-receipt.v2\0", &[receipt]),
        ))
    }
    pub(in crate::controller::operator_recovery_issuance) fn predecessor_cut(&self) -> [u8; 32] {
        self.predecessor_cut_at(self.predecessor_sequence)
    }

    pub(in crate::controller::operator_recovery_issuance) fn predecessor_cut_at(&self, sequence: u64) -> [u8; 32] {
        predecessor_cut_v4(sequence, &self.predecessor_current,
            &self.predecessor_projection, &self.predecessor_effect, &self.predecessor_operation)
    }

    /// Adds heldness to the existing derived transaction without changing its six-row boundary.
    pub(in crate::controller::operator_recovery_issuance) fn bind_actual_hold(
        self,
        journal: &Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        held: &HeldStorageTerminalV4<'_>,
        completion_wall_seconds: i64,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        if held.request().controller_cut() != self.predecessor_cut()
            || journal.snapshot_sequence() != self.predecessor_sequence
            || !self.predecessor_matches(journal)
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        self.bind_receipt_transaction(journal, signer, held, completion_wall_seconds)
    }

    /// Derives a definite no-commit ACK for an unchanged cut at a stale sequence.
    ///
    /// The returned commitments cannot be used to commit a successor. Storage
    /// must durably acknowledge this rejected original proposal before a fresh
    /// terminal query and proposal may be selected; physical Apply is unchanged.
    pub(in crate::controller::operator_recovery_issuance) fn stale_sequence_settlement(
        mut self,
        journal: &Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        held: &HeldStorageTerminalV4<'_>,
        completion_wall_seconds: i64,
        original_sequence: u64,
    ) -> Result<([u8; 32], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if self.predecessor_sequence <= original_sequence
            || journal.snapshot_sequence() != self.predecessor_sequence
            || !self.predecessor_matches(journal)
            || self.predecessor_cut_at(original_sequence) != held.request().controller_cut()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        // Only the proposal's sequence is retained in this rejected candidate.
        // The original four predecessor bytes must still match independently.
        self.predecessor_sequence = original_sequence;
        self.bind_receipt_transaction(journal, signer, held, completion_wall_seconds)?
            .settlement_commitments()
    }

    fn bind_receipt_transaction(
        mut self,
        journal: &Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        held: &HeldStorageTerminalV4<'_>,
        completion_wall_seconds: i64,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        let rows = self.transaction.records();
        let derived = BoundRepairLedgerReceiptV1::decode(rows[5].value().ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?)?;
        let receipt = HeldRepairLedgerReceiptV2::bind(derived, held, self.predecessor_sequence)?;
        let proof = super::StoredProofV2::decode(journal.get(RecordNamespace::OperatorRecovery,
            &[super::PREFIX, derived.operation_id.as_slice()].concat()).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?)?;
        if held.request().owner_pair_digest() != proof.signed_pair_digest {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let archive = exact_predecessor_archive(&receipt,
            rows[0].value().ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
            &self.predecessor_current, &self.predecessor_effect,
            &self.predecessor_operation, completion_wall_seconds)?;
        let pending = pending_operator_repair_ledger_v1(journal,
            OperationId::from_bytes(derived.operation_id), derived.sandbox_id,
            super::issued_intent(journal, signer, OperationId::from_bytes(derived.operation_id))?.0.public_request_digest)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let ledger = pending.complete(
            EffectReceipt::new(receipt.as_bytes().to_vec()).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
            completion_wall_seconds,
        ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let records = vec![
            JournalRecord::put(rows[0].namespace(), rows[0].key().to_vec(), archive),
            ledger[0].clone(), ledger[1].clone(), rows[3].clone(), rows[4].clone(),
            JournalRecord::put(rows[5].namespace(), rows[5].key().to_vec(), receipt.as_bytes().to_vec()),
        ];
        let digest = hash(COMMIT_DOMAIN, &[&derived.operation_id, receipt.as_bytes()]);
        self.transaction = JournalTransaction::new(
            digest[..16].try_into().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?, records,
        ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        Ok(self)
    }
    /// Prepares all six terminal rows from retained public and physical proof.
    ///
    /// The caller supplies a freshly challenged authenticated Storage inventory
    /// and a trusted Controller completion clock. Preparation does not keep
    /// Storage current across the subsequent journal commit.
    ///
    /// # Errors
    ///
    /// Rejects any missing, stale, or mismatched public admission, issuance,
    /// physical receipt, projection, proof, or protected predecessor head.
    pub(in crate::controller::operator_recovery_issuance) fn prepare(
        journal: &mut Journal,
        signer: &ProtectedOperatorRecoverySignerV1,
        owner: &ProtectedStorageRepairReceiptVerifierV2,
        operation_id: OperationId,
        storage_request_body: &[u8],
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
        completion_wall_seconds: i64,
    ) -> Result<Self, OperatorRecoveryIssuanceErrorV1> {
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let (issued, intent) = issued_intent(journal, signer, operation_id)?;
        let pending = pending_operator_repair_ledger_v1(
            journal,
            operation_id,
            intent.target_id,
            issued.public_request_digest,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let request = pending.request();
        let version_digest = hash(
            VERSION_DOMAIN,
            &[
                &(request.expected_resource_version().len() as u64).to_be_bytes(),
                request.expected_resource_version(),
            ],
        );
        let evidence_digest = hash(EVIDENCE_DOMAIN, &[&request.evidence().encode_to_vec()]);
        if intent.recovery_operation_id != *operation_id.as_bytes()
            || intent.project_id != *pending.context().project().as_bytes()
            || intent.principal_id != *pending.context().caller().as_bytes()
            || intent.request_digest != issued.public_request_digest
            || intent.expected_version_digest != version_digest
            || intent.evidence_digest != evidence_digest
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let current_key = recovery_current_key(intent.target_id);
        let predecessor_current = journal
            .get(RecordNamespace::OperatorRecovery, &current_key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        if hash(CURRENT_HEAD_DOMAIN_V2, &[&predecessor_current]) != issued.current_head_digest {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let predecessor = PublicProjectionStoreV1::new(journal)
            .get(PublicProjectionKindV1::Sandbox, intent.target_id)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        let PublicProjectionResourceV1::Sandbox(sandbox) = predecessor.resource() else {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        };
        if predecessor.project() != ProjectId::from_bytes(intent.project_id)
            || sandbox.resource_version != request.expected_resource_version()
            || intent.current_generation == 0
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let checked_predecessor = CheckedSandboxResourceV1::try_from(sandbox.clone())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let successor_projection = repair_sandbox_successor_projection_v1(
            &checked_predecessor,
            predecessor.project(),
            operation_id,
            issued.public_request_digest,
            request.expected_resource_version(),
            intent.current_generation,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let successor = successor_projection
            .checked_record()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let PublicProjectionResourceV1::Sandbox(successor_sandbox) = successor.resource() else {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        };
        let checked_successor = CheckedSandboxResourceV1::try_from(successor_sandbox.clone())
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let successor_current = operator_repair_successor_current_v1(
            &predecessor_current,
            &checked_predecessor,
            &checked_successor,
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let predecessor_projection = journal
            .get(
                RecordNamespace::DesiredState,
                successor_projection.desired_key(),
            )
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        let receipt = BoundRepairLedgerReceiptV1::from_current_verified_rows(
            journal,
            signer,
            owner,
            operation_id,
            storage_request_body,
            &predecessor_projection,
            &successor_projection,
            &successor_current,
            fresh,
        )?;
        let archive = receipt.prepare_predecessor_archive(
            journal,
            &successor_projection,
            issued.current_head_digest,
        )?;
        let ledger = pending
            .complete(
                EffectReceipt::new(receipt.encode().to_vec())
                    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?,
                completion_wall_seconds,
            )
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let predecessor_effect = journal
            .get(ledger[0].namespace(), ledger[0].key())
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        let predecessor_operation = journal
            .get(ledger[1].namespace(), ledger[1].key())
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?
            .to_vec();
        let terminal_key = [TERMINAL_RECEIPT_PREFIX, operation_id.as_bytes()].concat();
        if journal
            .get(RecordNamespace::OperatorRecovery, &terminal_key)
            .is_some()
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let receipt_bytes = receipt.encode();
        let digest = hash(COMMIT_DOMAIN, &[operation_id.as_bytes(), &receipt_bytes]);
        let transaction_id: [u8; 16] = digest[..16]
            .try_into()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let transaction = JournalTransaction::new(
            transaction_id,
            vec![
                archive,
                ledger[0].clone(),
                ledger[1].clone(),
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    successor_projection.desired_key().to_vec(),
                    successor_projection.desired_value().to_vec(),
                ),
                JournalRecord::put(
                    RecordNamespace::OperatorRecovery,
                    current_key,
                    successor_current,
                ),
                JournalRecord::put(
                    RecordNamespace::OperatorRecovery,
                    terminal_key,
                    receipt_bytes.to_vec(),
                ),
            ],
        )
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;

        Ok(Self {
            transaction,
            predecessor_sequence: journal.snapshot_sequence(),
            predecessor_current,
            predecessor_projection,
            predecessor_effect,
            predecessor_operation,
        })
    }

    /// Commits the exact successor or reports a locally ambiguous outcome.
    ///
    /// # Errors
    ///
    /// Rejects an unhealthy authority or stale predecessor before committing.
    pub(in crate::controller::operator_recovery_issuance) fn commit(
        &self,
        journal: &mut Journal,
    ) -> Result<RepairSuccessorCommitOutcomeV1, OperatorRecoveryIssuanceErrorV1> {
        journal
            .ensure_protected_authority()
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        if self.successor_matches(journal) {
            return Ok(RepairSuccessorCommitOutcomeV1::Replay);
        }
        if !self.predecessor_matches(journal) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        // Every copied Controller dependency must remain current, including
        // authorization and issuance rows outside the terminal write set.
        if journal.snapshot_sequence() != self.predecessor_sequence {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }

        let result = journal.commit(&self.transaction);
        // An append or cache-readback error does not prove durable absence.
        // Only healthy, exact protected readback can settle the held owner.
        match self.classify_ambiguous(journal)? {
            RepairSuccessorCommitOutcomeV1::Replay if result.is_ok() => {
                Ok(RepairSuccessorCommitOutcomeV1::Committed)
            }
            outcome => Ok(outcome),
        }
    }

    /// Resolves a post-commit uncertainty using only exact protected rows.
    ///
    /// # Errors
    ///
    /// Reports unhealthy, partial, or conflicting readback as an ambiguous
    /// outcome rather than an error. A definite non-commit requires the exact
    /// unchanged predecessor and its sequence.
    pub(in crate::controller::operator_recovery_issuance) fn classify_ambiguous(
        &self,
        journal: &Journal,
    ) -> Result<RepairSuccessorCommitOutcomeV1, OperatorRecoveryIssuanceErrorV1> {
        if journal.ensure_protected_authority().is_err() {
            return Ok(RepairSuccessorCommitOutcomeV1::Ambiguous);
        }
        if self.successor_matches(journal) {
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        } else if self.predecessor_matches(journal)
            && journal.snapshot_sequence() == self.predecessor_sequence
        {
            Ok(RepairSuccessorCommitOutcomeV1::NotCommitted)
        } else {
            Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
        }
    }

    fn successor_matches(&self, journal: &Journal) -> bool {
        self.transaction
            .records()
            .iter()
            .all(|record| journal.get(record.namespace(), record.key()) == record.value())
    }

    fn predecessor_matches(&self, journal: &Journal) -> bool {
        let records = self.transaction.records();
        journal.get(records[1].namespace(), records[1].key())
            == Some(self.predecessor_effect.as_slice())
            && journal.get(records[2].namespace(), records[2].key())
                == Some(self.predecessor_operation.as_slice())
            && journal.get(records[3].namespace(), records[3].key())
                == Some(self.predecessor_projection.as_slice())
            && journal.get(records[4].namespace(), records[4].key())
                == Some(self.predecessor_current.as_slice())
            && journal
                .get(records[0].namespace(), records[0].key())
                .is_none()
            && journal
                .get(records[5].namespace(), records[5].key())
                .is_none()
    }
}

fn predecessor_cut_v4(
    sequence: u64,
    current: &[u8],
    projection: &[u8],
    effect: &[u8],
    operation: &[u8],
) -> [u8; 32] {
    hash(b"aos.sandbox.operator-repair-controller-predecessor-cut.v4\0", &[
        &sequence.to_be_bytes(), current, projection, effect, operation,
    ])
}

/// Verifies all six exact terminal rows and original authenticated history.
pub(in crate::controller::operator_recovery_issuance) fn verify_current_terminal_v2(
    journal: &mut Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    owner: &ProtectedStorageRepairReceiptVerifierV2,
    operation: OperationId,
    storage_body: &[u8],
    fresh: Option<&AuthenticatedBrokerMethodOutcomeV1>,
) -> Result<([u8; 32], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
    journal.ensure_protected_authority().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let terminal_key = [TERMINAL_RECEIPT_PREFIX, operation.as_bytes()].concat();
    let receipt_bytes = journal.get(RecordNamespace::OperatorRecovery, &terminal_key)
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?.to_vec();
    let receipt = HeldRepairLedgerReceiptV2::verify(&receipt_bytes, signer, owner)?;
    let derived = receipt.derived()?;
    derived.verify_retained_rows_except_freshness(journal, signer, owner)?;
    let (issued, intent) = issued_intent(journal, signer, operation)?;
    let owner_facts = super::super::receipt::verified_retained_repair_receipt_v3(journal, &intent, owner)?;
    let claims = receipt.retained_request(signer)?;
    if derived.operation_id != *operation.as_bytes()
        || claims.signed_intent() != issued.signed_intent
        || claims.owner_pair_digest() != owner_facts.signed_pair_digest
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let challenge = super::super::probe_challenge::read(journal, &issued, intent.effect_id,
        super::super::probe_challenge::ProbeStageV1::Terminal, owner_facts.signed_pair_digest)?;
    if claims.signed_header()[444..460] != challenge.request_id() {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    if let Some(fresh) = fresh {
        challenge.matches_outcome(fresh)?;
        if claims.signed_header()[460..492] != hash(b"aos.sandbox.operator-repair-terminal-fresh-packet.v1\0", &[fresh.canonical_packet()]) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        super::ledger_receipt::verify_fresh_physical_target(&owner_facts, &intent, storage_body, fresh)?;
    }
    let archive_key = [b"storage-repair-predecessor-v1/".as_slice(), operation.as_bytes()].concat();
    let archive = journal.get(RecordNamespace::OperatorRecovery, &archive_key)
        .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?.to_vec();
    let predecessor = receipt.verify_exact_archive(&archive, issued.current_head_digest)?;
    let cut = predecessor_cut_v4(receipt.predecessor_sequence()?, &predecessor.current,
        &predecessor.projection, &predecessor.effect, &predecessor.operation);
    if cut != receipt.controller_cut() {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    crate::reconciler::verify_operator_repair_terminal_public_rows_v2(journal, operation,
        intent.target_id, issued.public_request_digest, &predecessor.operation,
        &predecessor.effect, &receipt_bytes, predecessor.completion_wall_seconds)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;

    let projection = PublicProjectionRecordV1::from_retained_record_bytes(
        PublicProjectionKindV1::Sandbox, intent.target_id, &predecessor.projection,
    ).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let PublicProjectionResourceV1::Sandbox(sandbox) = projection.resource() else {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    };
    let checked = CheckedSandboxResourceV1::try_from(sandbox.clone())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let successor = repair_sandbox_successor_projection_v1(&checked, projection.project(), operation,
        issued.public_request_digest, &sandbox.resource_version, intent.current_generation)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let successor_record = successor.checked_record().map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let PublicProjectionResourceV1::Sandbox(successor_sandbox) = successor_record.resource() else {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    };
    let checked_successor = CheckedSandboxResourceV1::try_from(successor_sandbox.clone())
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    let current = operator_repair_successor_current_v1(&predecessor.current, &checked, &checked_successor)
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    if journal.get(RecordNamespace::DesiredState, successor.desired_key()) != Some(successor.desired_value())
        || journal.get(RecordNamespace::OperatorRecovery, &recovery_current_key(intent.target_id)) != Some(current.as_slice())
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }
    let effect_key = [operation.as_bytes().as_slice(), &0_u32.to_be_bytes()].concat();
    let rows = [
        JournalRecord::put(RecordNamespace::OperatorRecovery, archive_key, archive),
        JournalRecord::put(RecordNamespace::Effect, effect_key.clone(), journal.get(RecordNamespace::Effect, &effect_key).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?.to_vec()),
        JournalRecord::put(RecordNamespace::Operation, operation.as_bytes().to_vec(), journal.get(RecordNamespace::Operation, operation.as_bytes()).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?.to_vec()),
        JournalRecord::put(RecordNamespace::DesiredState, successor.desired_key().to_vec(), successor.desired_value().to_vec()),
        JournalRecord::put(RecordNamespace::OperatorRecovery, recovery_current_key(intent.target_id), current),
        JournalRecord::put(RecordNamespace::OperatorRecovery, terminal_key, receipt_bytes.clone()),
    ];
    let transaction_id = hash(COMMIT_DOMAIN, &[operation.as_bytes(), &receipt_bytes]);
    let transaction_id = transaction_id[..16]
        .try_into()
        .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
    Ok((exact_transaction_digest(&transaction_id, &rows)?, receipt.digest()))
}

pub(super) fn exact_transaction_digest(
    transaction_id: &[u8; 16],
    records: &[JournalRecord],
) -> Result<[u8; 32], OperatorRecoveryIssuanceErrorV1> {
    let mut digest = Sha256::new()
        .chain_update(b"aos.sandbox.operator-repair-exact-terminal-transaction.v4\0")
        .chain_update(transaction_id);
    for record in records {
        let value = record.value().ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        digest.update([record.namespace() as u8]);
        digest.update((record.key().len() as u64).to_be_bytes());
        digest.update(record.key());
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }

    Ok(digest.finalize().into())
}

/// Joins an owner-signed release to its retained terminal receipt for scheduling.
///
/// This historical check does not require the Sandbox to remain at its old
/// successor forever, and cannot open Storage or recreate a live hold.
pub(in crate::controller::operator_recovery_issuance) fn verify_settled_terminal_receipt_v2(
    journal: &Journal,
    signer: &ProtectedOperatorRecoverySignerV1,
    owner: &ProtectedStorageRepairReceiptVerifierV2,
    operation: OperationId,
    request_cut: [u8; 32],
    expected_receipt: [u8; 32],
) -> Result<(), OperatorRecoveryIssuanceErrorV1> {
    let key = [TERMINAL_RECEIPT_PREFIX, operation.as_bytes()].concat();
    let receipt = HeldRepairLedgerReceiptV2::verify(
        journal.get(RecordNamespace::OperatorRecovery, &key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
        signer, owner,
    )?;
    if receipt.digest() != expected_receipt
        || receipt.derived()?.operation_id != *operation.as_bytes()
        || receipt.retained_request(signer)?.cut_digest() != request_cut
    {
        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::JournalLimits;

    fn open_journal(directory: &tempfile::TempDir) -> Journal {
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        Journal::open_protected_at_uid(
            directory.path(),
            "repair-successor.journal",
            JournalLimits::default(),
            rustix::process::getuid().as_raw(),
        )
        .unwrap()
        .0
    }

    fn seeded() -> (tempfile::TempDir, Journal, PreparedRepairSuccessorV1) {
        let directory = tempfile::tempdir().unwrap();
        let mut journal = open_journal(&directory);
        let operation_id = [7; 16];
        let effect_key = [operation_id.as_slice(), &[0; 4]].concat();
        let operation_key = operation_id.to_vec();
        let projection_key = b"sandbox-projection".to_vec();
        let current_key = recovery_current_key([8; 16]);
        let archive_key = b"repair-archive".to_vec();
        let receipt_key = b"repair-terminal-receipt".to_vec();
        let predecessor_effect = b"effect-pending".to_vec();
        let predecessor_operation = b"operation-applying".to_vec();
        let predecessor_projection = b"projection-before".to_vec();
        let predecessor_current = b"head-before".to_vec();
        journal
            .commit(
                &JournalTransaction::new(
                    [9; 16],
                    vec![
                        JournalRecord::put(
                            RecordNamespace::Effect,
                            effect_key.clone(),
                            predecessor_effect.clone(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::Operation,
                            operation_key.clone(),
                            predecessor_operation.clone(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::DesiredState,
                            projection_key.clone(),
                            predecessor_projection.clone(),
                        ),
                        JournalRecord::put(
                            RecordNamespace::OperatorRecovery,
                            current_key.clone(),
                            predecessor_current.clone(),
                        ),
                    ],
                )
                .unwrap(),
            )
            .unwrap();
        let transaction = JournalTransaction::new(
            [10; 16],
            vec![
                JournalRecord::put(RecordNamespace::OperatorRecovery, archive_key, vec![11]),
                JournalRecord::put(RecordNamespace::Effect, effect_key, vec![12]),
                JournalRecord::put(RecordNamespace::Operation, operation_key, vec![13]),
                JournalRecord::put(RecordNamespace::DesiredState, projection_key, vec![14]),
                JournalRecord::put(RecordNamespace::OperatorRecovery, current_key, vec![15]),
                JournalRecord::put(RecordNamespace::OperatorRecovery, receipt_key, vec![16]),
            ],
        )
        .unwrap();
        let prepared = PreparedRepairSuccessorV1 {
            transaction,
            predecessor_sequence: journal.snapshot_sequence(),
            predecessor_current,
            predecessor_projection,
            predecessor_effect,
            predecessor_operation,
        };
        (directory, journal, prepared)
    }

    #[test]
    fn successor_commits_all_six_rows_and_replays_after_reopen() {
        let (directory, mut journal, prepared) = seeded();
        let predecessor_sequence = journal.snapshot_sequence();
        assert_eq!(
            prepared.classify_ambiguous(&journal),
            Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
        );
        assert_eq!(
            prepared.commit(&mut journal),
            Ok(RepairSuccessorCommitOutcomeV1::Committed)
        );
        assert!(journal.snapshot_sequence() > predecessor_sequence);
        drop(journal);

        let mut reopened = open_journal(&directory);
        assert_eq!(
            prepared.classify_ambiguous(&reopened),
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        );
        assert_eq!(
            prepared.commit(&mut reopened),
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        );
        assert!(prepared.successor_matches(&reopened));
    }

    #[test]
    fn an_unrelated_journal_append_never_silently_rebases_the_terminal_cas() {
        let (_directory, mut journal, prepared) = seeded();
        let original_sequence = journal.snapshot_sequence();
        let original_cut = prepared.predecessor_cut();
        journal.commit(&JournalTransaction::new(
            [19; 16],
            vec![JournalRecord::put(RecordNamespace::OperatorRecovery, b"unrelated".to_vec(), vec![20])],
        ).unwrap()).unwrap();

        assert!(prepared.predecessor_matches(&journal));
        assert_eq!(prepared.predecessor_cut_at(original_sequence), original_cut);
        assert_ne!(prepared.predecessor_cut_at(journal.snapshot_sequence()), original_cut);
        assert!(prepared.commit(&mut journal).is_err());

        for index in [0, 5] {
            let row = &prepared.transaction.records()[index];
            assert!(journal.get(row.namespace(), row.key()).is_none());
        }
    }

    #[test]
    fn every_public_predecessor_substitution_rejects_without_terminal_rows() {
        for index in 1..=4 {
            let (_directory, mut journal, prepared) = seeded();
            let row = &prepared.transaction.records()[index];
            journal.commit(&JournalTransaction::new(
                [21; 16],
                vec![JournalRecord::put(row.namespace(), row.key().to_vec(), b"replaced".to_vec())],
            ).unwrap()).unwrap();

            assert!(!prepared.predecessor_matches(&journal));
            assert!(prepared.commit(&mut journal).is_err());
            assert_eq!(
                prepared.classify_ambiguous(&journal),
                Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
            );
            for terminal in [0, 5] {
                let row = &prepared.transaction.records()[terminal];
                assert!(journal.get(row.namespace(), row.key()).is_none());
            }
        }
    }

    #[test]
    fn exact_settlement_digest_commits_row_order_namespace_keys_and_full_values() {
        let (_directory, _journal, prepared) = seeded();
        let rows = prepared.transaction.records();
        let original = exact_transaction_digest(prepared.transaction.id(), rows).unwrap();

        let mut swapped = rows.to_vec();
        swapped.swap(0, 1);
        assert_ne!(exact_transaction_digest(prepared.transaction.id(), &swapped).unwrap(), original);
        assert_ne!(exact_transaction_digest(&[22; 16], rows).unwrap(), original);

        for replacement in [
            JournalRecord::put(RecordNamespace::Operation, rows[0].key().to_vec(), vec![11]),
            JournalRecord::put(rows[0].namespace(), b"other archive".to_vec(), vec![11]),
            JournalRecord::put(rows[0].namespace(), rows[0].key().to_vec(), vec![11, 0]),
        ] {
            let mut changed = rows.to_vec();
            changed[0] = replacement;
            assert_ne!(exact_transaction_digest(prepared.transaction.id(), &changed).unwrap(), original);
        }
    }

    #[test]
    fn ambiguous_post_durable_error_resolves_only_exact_successor() {
        let (_directory, mut journal, prepared) = seeded();
        // Models an error returned after the complete journal transaction is
        // durable, before the caller receives its commit result.
        journal.commit(&prepared.transaction).unwrap();
        assert_eq!(
            prepared.classify_ambiguous(&journal),
            Ok(RepairSuccessorCommitOutcomeV1::Replay)
        );

        let operation = &prepared.transaction.records()[2];
        journal
            .commit(
                &JournalTransaction::new(
                    [17; 16],
                    vec![JournalRecord::put(
                        operation.namespace(),
                        operation.key().to_vec(),
                        b"substituted-operation".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            prepared.classify_ambiguous(&journal),
            Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
        );
    }

    #[test]
    fn stale_predecessor_rejects_terminal_commit_without_partial_rows() {
        let (_directory, mut journal, prepared) = seeded();
        let current = &prepared.transaction.records()[4];
        journal
            .commit(
                &JournalTransaction::new(
                    [18; 16],
                    vec![JournalRecord::put(
                        current.namespace(),
                        current.key().to_vec(),
                        b"another-current-head".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();
        assert!(prepared.commit(&mut journal).is_err());
        assert!(
            journal
                .get(
                    prepared.transaction.records()[5].namespace(),
                    prepared.transaction.records()[5].key(),
                )
                .is_none()
        );
    }

    #[test]
    fn unrelated_controller_write_invalidates_prepared_dependency_snapshot() {
        let (_directory, mut journal, prepared) = seeded();
        journal
            .commit(
                &JournalTransaction::new(
                    [19; 16],
                    vec![JournalRecord::put(
                        RecordNamespace::PublicOperationAuthorization,
                        b"other-admission".to_vec(),
                        b"changed".to_vec(),
                    )],
                )
                .unwrap(),
            )
            .unwrap();

        assert!(prepared.predecessor_matches(&journal));
        assert!(prepared.commit(&mut journal).is_err());
        assert_eq!(
            prepared.classify_ambiguous(&journal),
            Ok(RepairSuccessorCommitOutcomeV1::Ambiguous)
        );
        assert!(
            journal
                .get(
                    prepared.transaction.records()[5].namespace(),
                    prepared.transaction.records()[5].key(),
                )
                .is_none()
        );
    }
}
