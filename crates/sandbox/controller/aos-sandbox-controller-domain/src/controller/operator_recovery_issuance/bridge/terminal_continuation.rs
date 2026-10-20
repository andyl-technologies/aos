//! Exact original terminal proposal, actual-held CAS and same-child settlement.
//!
//! The single proposal-custody write precedes the Storage crossing and is
//! included in the exact predecessor sequence. No witness write occurs before
//! CAS: its complete signed bytes belong to the six-row terminal transaction.
//! Ambiguity preserves the original proposal and never repeats physical Apply.

use aos_sandbox_protocol::authenticated_session::all_methods::AuthenticatedBrokerMethodResultV1;
use aos_sandbox_protocol::operator_storage_repair_terminal_v4::{
    RepairTerminalDispositionV4, RepairTerminalModeV4, RepairTerminalRequestV4,
    RepairTerminalSettlementV4,
};
use ed25519_dalek::SigningKey;

use super::*;
use super::super::terminal::{ObservedRepairPreconditionV1, PreparedRepairPreconditionFailureV1,
    PreparedRepairSuccessorV1, RepairSuccessorCommitOutcomeV1};
use super::super::transport::{HeldStorageTerminalV4, StorageTerminalAcquisitionV4, coordinates};

impl OperatorStorageRepairBridgeV1<'_> {
    pub(super) fn terminal_epoch(&self, operation: OperationId) -> Result<u8, OperatorRecoveryIssuanceErrorV1> {
        for epoch in 0..MAXIMUM_TERMINAL_EPOCHS {
            let Some(readback) = self.progress(operation, terminal_phase(SETTLEMENT_READBACK, epoch))? else {
                return Ok(epoch);
            };
            let proposal = self.progress(operation, terminal_phase(HOLD_REQUEST, epoch))?
                .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
            let original = RepairTerminalRequestV4::verify(proposal.get(16..).ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?,
                self.signer.verifier(), self.signer.generation()).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
            let ack = super::super::transport::verify_retained_terminal_readback_v4(&readback, original.cut_digest(), &self.signer, &self.owner)?;
            if ack.disposition() != RepairTerminalDispositionV4::NotCommitted {
                return Ok(epoch);
            }
        }
        Err(OperatorRecoveryIssuanceErrorV1::Binding)
    }

    /// Completes one original Repair under actual Storage heldness and exact journal CAS.
    ///
    /// All four outcomes must come from the real session owner or its separately
    /// verified historical custody. A retained signed packet is never promoted
    /// to a live owner. Recovery resends only the original terminal proposal;
    /// it does not issue Prepare, Execute, or an ordinary query while held.
    ///
    /// # Errors
    ///
    /// Rejects substituted admission/history/cuts or role custody. Any possibly
    /// sent hold, uncertain CAS or lost ACK preserves original outcome-unknown.
    #[allow(clippy::too_many_arguments)]
    pub fn complete_terminal(
        &mut self,
        operation: OperationId,
        admission: &AuthenticatedBrokerMethodOutcomeV1,
        before: &AuthenticatedBrokerMethodOutcomeV1,
        after: &AuthenticatedBrokerMethodOutcomeV1,
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
        storage: &ResourceInventoryServiceIdentity,
        completion_wall_seconds: i64,
    ) -> Result<OperatorStorageRepairTerminalV1, OperatorRecoveryIssuanceErrorV1> {
        let (body, _) = self.original_request(operation)?;
        let snapshot = self.progress_snapshot(operation)?;
        if admission.request().request_id() != snapshot.admission_request_id
            || admission.canonical_packet() != snapshot.admission_packet
        {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        crate::lifecycle::LifecycleAuthenticatedStorageInventoryV1::from_authenticated_outcome(admission)
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let attempt_key = [super::super::admission::ATTEMPT_PREFIX, operation.as_bytes()].concat();
        let attempt = self.journal.0.get(RecordNamespace::OperatorRecovery, &attempt_key)
            .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
        if &attempt[96..128] != hash(b"aos.sandbox.operator-repair-admission-packet.v1\0", &[admission.canonical_packet()]) {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        super::super::terminal::verify_authenticated_repair_history_v4(
            self.journal.0, &self.signer, &self.owner, operation, before, after, fresh,
        )?;
        let epoch = self.terminal_epoch(operation)?;
        self.retain_progress(operation, terminal_phase(TERMINAL_PACKET, epoch), fresh.canonical_packet())?;

        let terminal_key = [b"storage-repair-terminal-v1/".as_slice(), operation.as_bytes()].concat();
        let committed = self.journal.0.get(RecordNamespace::OperatorRecovery, &terminal_key).is_some();
        let (original, clock, original_sequence) = match self.progress(operation, terminal_phase(HOLD_REQUEST, epoch))? {
            Some(bytes) => {
                if bytes.len() < 16 { return Err(OperatorRecoveryIssuanceErrorV1::Binding); }
                let clock = i64::from_be_bytes(super::super::take_array(&bytes, 0)?);
                let sequence = u64::from_be_bytes(super::super::take_array(&bytes, 8)?);
                let request = RepairTerminalRequestV4::verify(&bytes[16..], self.signer.verifier(), self.signer.generation())
                    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
                (request, clock, sequence)
            }
            None => {
                if committed { return Err(OperatorRecoveryIssuanceErrorV1::Binding); }
                // This closed custody write appends exactly one record. The
                // native snapshot counts Begin, Record, and Commit frames, so
                // the signed predecessor cut is the checked post-write cut.
                let sequence = self.journal.0.snapshot_sequence().checked_add(3)
                    .ok_or(OperatorRecoveryIssuanceErrorV1::Binding)?;
                let observed = ObservedRepairPreconditionV1::capture(
                    self.journal.0, &self.signer, operation,
                )?;
                let (cut, proof, query, packet) = if observed.is_replaced() {
                    let (proof, query, packet) = super::super::terminal::failure_terminal_claims_v1(
                        self.journal.0, &self.signer, &self.owner, operation, &body, fresh,
                    )?;
                    (observed.predecessor_cut_at(sequence), proof, query, packet)
                } else {
                    let prepared = PreparedRepairSuccessorV1::prepare(self.journal.0, &self.signer,
                        &self.owner, operation, &body, fresh, completion_wall_seconds)?;
                    let (proof, query, packet) = prepared.terminal_claims()?;
                    (prepared.predecessor_cut_at(sequence), proof, query, packet)
                };
                let (issued, _) = super::super::terminal::issued_intent(self.journal.0, &self.signer, operation)?;
                let pair = super::super::terminal::terminal_owner_pair_v4(self.journal.0, &self.signer, &self.owner, operation)?;
                let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = fresh.result() else {
                    return Err(OperatorRecoveryIssuanceErrorV1::Binding);
                };
                let (request, deadline) = coordinates()?;
                self.signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
                let original = RepairTerminalRequestV4::sign(RepairTerminalModeV4::Hold, request,
                    deadline, self.signer.generation(), issued.signed_intent,
                    cut, query, packet, proof, pair,
                    exact_body.to_vec(), &SigningKey::from_bytes(&self.signer.seed))
                    .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
                let mut custody = completion_wall_seconds.to_be_bytes().to_vec();
                custody.extend_from_slice(&sequence.to_be_bytes());
                custody.extend_from_slice(&original.encode());
                self.retain_progress(operation, terminal_phase(HOLD_REQUEST, epoch), &custody)?;
                if self.journal.0.snapshot_sequence() != sequence {
                    return Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown);
                }
                (original, completion_wall_seconds, sequence)
            }
        };
        let AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } = fresh.result() else {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        };
        let (issued, _) = super::super::terminal::issued_intent(self.journal.0, &self.signer, operation)?;
        if original.signed_intent() != issued.signed_intent || original.inventory() != exact_body {
            return Err(OperatorRecoveryIssuanceErrorV1::Binding);
        }
        let recovery = snapshot.terminal_hold_sent || committed;
        let request = if recovery { reconnect_original(&original, &self.signer)? } else { original };
        let verified_commit = if committed {
            let failure = self.journal.0.get(RecordNamespace::OperatorRecovery, &terminal_key)
                .is_some_and(|bytes| bytes.starts_with(b"AOSORF01"));
            if failure {
                let (commit, receipt) = super::super::terminal::verify_current_failure_v1(
                    self.journal.0, &self.signer, &self.owner, operation, Some((&body, fresh)),
                )?;
                Some((RepairTerminalDispositionV4::OriginalPreconditionReplaced, commit, receipt))
            } else {
                let (commit, receipt) = super::super::terminal::verify_current_terminal_v2(
                    self.journal.0, &self.signer, &self.owner, operation, &body, Some(fresh),
                )?;
                Some((RepairTerminalDispositionV4::Committed, commit, receipt))
            }
        } else {
            None
        };
        let acquisition = HeldStorageTerminalV4::acquire(request, storage, &self.owner, &self.signer)?;
        let held = match acquisition {
            StorageTerminalAcquisitionV4::Settled(ack, readback) => {
                let Some((disposition, commit, receipt)) = verified_commit else {
                    if ack.disposition() != RepairTerminalDispositionV4::NotCommitted {
                        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
                    }
                    let prepared = PreparedRepairSuccessorV1::prepare(self.journal.0, &self.signer,
                        &self.owner, operation, &body, fresh, clock)?;
                    if prepared.predecessor_cut_at(original_sequence) != original_controller_cut(&readback)?
                        || self.journal.0.get(RecordNamespace::OperatorRecovery,
                            &[b"storage-repair-predecessor-v1/".as_slice(), operation.as_bytes()].concat()).is_some()
                    {
                        return Err(OperatorRecoveryIssuanceErrorV1::Binding);
                    }
                    self.retain_progress(operation, terminal_phase(SETTLEMENT_READBACK, epoch), &readback)?;
                    return Ok(OperatorStorageRepairTerminalV1::NotCommitted);
                };
                if ack.disposition() != disposition
                    || ack.terminal_commit() != commit || ack.receipt_digest() != receipt
                {
                    return Err(OperatorRecoveryIssuanceErrorV1::Binding);
                }
                self.retain_progress(operation, terminal_phase(SETTLEMENT_READBACK, epoch), &readback)?;
                return Ok(if disposition == RepairTerminalDispositionV4::OriginalPreconditionReplaced {
                    OperatorStorageRepairTerminalV1::OriginalPreconditionReplaced
                } else {
                    OperatorStorageRepairTerminalV1::Replay
                });
            }
            StorageTerminalAcquisitionV4::Held(held) => held,
        };

        let (outcome, disposition, commit, receipt) = match verified_commit {
            Some((disposition, commit, receipt)) => (
                if disposition == RepairTerminalDispositionV4::OriginalPreconditionReplaced {
                    OperatorStorageRepairTerminalV1::OriginalPreconditionReplaced
                } else {
                    OperatorStorageRepairTerminalV1::Replay
                }, disposition, commit, receipt,
            ),
            None => {
                // Select failure only from a separately checked replacement.
                // Binding failures in admission, physical proof, floors or
                // history are never caught and converted into this decision.
                let observed = ObservedRepairPreconditionV1::capture(
                    self.journal.0, &self.signer, operation,
                )?;
                if observed.is_replaced() {
                    held.recheck(&self.owner)?;
                    self.signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
                    let prepared = PreparedRepairPreconditionFailureV1::prepare(
                        self.journal.0, &self.signer, &self.owner, operation,
                        &body, fresh, &held, clock,
                    )?;
                    match prepared.commit(self.journal.0)? {
                        RepairSuccessorCommitOutcomeV1::Committed | RepairSuccessorCommitOutcomeV1::Replay => {}
                        RepairSuccessorCommitOutcomeV1::NotCommitted | RepairSuccessorCommitOutcomeV1::Ambiguous => {
                            // An absent failure decision is not physical absence.
                            // Keep the same hold and retry its exact public CAS;
                            // never publish a false NoCommit/rollback decision.
                            return Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown);
                        }
                    }
                    let (commit, receipt) = prepared.settlement_commitments()?;
                    let exact = super::super::terminal::verify_current_failure_v1(
                        self.journal.0, &self.signer, &self.owner, operation, Some((&body, fresh)),
                    )?;
                    if exact != (commit, receipt) {
                        return Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown);
                    }
                    (OperatorStorageRepairTerminalV1::OriginalPreconditionReplaced,
                        RepairTerminalDispositionV4::OriginalPreconditionReplaced, commit, receipt)
                } else {
                    self.commit_unchanged_success(
                        operation, &body, fresh, &held, clock, original_sequence,
                    )?
                }
            }
        };
        held.recheck(&self.owner)?;
        self.signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;
        let ack = RepairTerminalSettlementV4::sign(disposition, held.request().request_id(),
            held.request().deadline(), self.signer.generation(), held.witness(), commit, receipt,
            &SigningKey::from_bytes(&self.signer.seed))
            .map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)?;
        let readback = held.settle(ack, &self.owner)?;
        self.retain_progress(operation, terminal_phase(SETTLEMENT_READBACK, epoch), &readback)?;
        Ok(outcome)
    }

    fn commit_unchanged_success(
        &mut self,
        operation: OperationId,
        body: &[u8],
        fresh: &AuthenticatedBrokerMethodOutcomeV1,
        held: &HeldStorageTerminalV4<'_>,
        clock: i64,
        original_sequence: u64,
    ) -> Result<(OperatorStorageRepairTerminalV1, RepairTerminalDispositionV4, [u8; 32], [u8; 32]), OperatorRecoveryIssuanceErrorV1> {
        let prepared = PreparedRepairSuccessorV1::prepare(
            self.journal.0, &self.signer, &self.owner, operation, body, fresh, clock,
        )?;
        held.recheck(&self.owner)?;
        self.signer.credential.recheck().map_err(|_| OperatorRecoveryIssuanceErrorV1::Key)?;

        if prepared.predecessor_cut() != held.request().controller_cut() {
            let (commit, receipt) = prepared.stale_sequence_settlement(
                self.journal.0, &self.signer, held, clock, original_sequence,
            )?;
            return Ok((OperatorStorageRepairTerminalV1::NotCommitted,
                RepairTerminalDispositionV4::NotCommitted, commit, receipt));
        }
        let prepared = prepared.bind_actual_hold(self.journal.0, &self.signer, held, clock)?;
        let mut result = prepared.commit(self.journal.0)?;
        if result == RepairSuccessorCommitOutcomeV1::Ambiguous {
            result = prepared.classify_ambiguous(self.journal.0)?;
        }

        let (commit, receipt) = prepared.settlement_commitments()?;
        let (outcome, disposition) = match result {
            RepairSuccessorCommitOutcomeV1::Committed => (
                OperatorStorageRepairTerminalV1::Committed, RepairTerminalDispositionV4::Committed,
            ),
            RepairSuccessorCommitOutcomeV1::Replay => (
                OperatorStorageRepairTerminalV1::Replay, RepairTerminalDispositionV4::Committed,
            ),
            RepairSuccessorCommitOutcomeV1::NotCommitted => (
                OperatorStorageRepairTerminalV1::NotCommitted, RepairTerminalDispositionV4::NotCommitted,
            ),
            RepairSuccessorCommitOutcomeV1::Ambiguous => {
                return Err(OperatorRecoveryIssuanceErrorV1::OutcomeUnknown);
            }
        };
        Ok((outcome, disposition, commit, receipt))
    }
}

fn original_controller_cut(readback: &[u8]) -> Result<[u8; 32], OperatorRecoveryIssuanceErrorV1> {
    super::super::take_array(readback, 8 + 412)
}

fn reconnect_original(original: &RepairTerminalRequestV4, signer: &ProtectedOperatorRecoverySignerV1) -> Result<RepairTerminalRequestV4, OperatorRecoveryIssuanceErrorV1> {
    let (request, deadline) = coordinates()?;
    let header = original.signed_header();
    RepairTerminalRequestV4::sign(RepairTerminalModeV4::Recover, request, deadline,
        original.controller_generation(), original.signed_intent(), original.controller_cut(),
        super::super::take_array(header, 444)?, super::super::take_array(header, 460)?,
        original.proof_digest(), original.owner_pair_digest(), original.inventory().to_vec(),
        &SigningKey::from_bytes(&signer.seed)).map_err(|_| OperatorRecoveryIssuanceErrorV1::Binding)
}
