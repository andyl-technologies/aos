//! Dormant protected-journal implementation of agent checkpoint and CAS stores.
//!
//! This module performs no guest or transport effect. It persists exact
//! reservations, outcomes, sequence heads, and `AOSAGC01` checkpoints in a
//! separately owned protected journal.
//!
//! ```text
//! AOSAGO02 || phase:u8 || session[32] || sequence:u64be
//! || operation[16] || request[32] || store_commitment[32]
//! || reservation_sequence:u64be || recovered:u8 || recovery_provenance[32]
//! || request_frame_length:u32be || AOSAGE01_request
//! || outcome_frame_length:u32be || optional_AOSAGE01_outcome
//!
//! AOSAGS01 || request_frame_length:u32be || AOSAGE01_handshake_request
//! || response_frame_length:u32be || AOSAGE01_handshake_response
//! ```

use aos_sandbox_agent::{
    AgentExecutionOutcomeV1, AgentFrameV1, AgentHandshakeRequestV1, AgentHandshakeResponseV1,
    AgentOperationIdV1, AgentOperationRequestV1, AgentOperationSequenceV1, AgentSessionBindingV1,
    decode_frame_v1, encode_frame_v1,
};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};

use super::agent_checkpoint::{
    AgentCheckpointCandidateV1, AgentCheckpointError, AgentDurableCheckpointV1,
    decode_checkpoint_v1,
};
use super::agent_reducer::{
    AgentDurableHistoryRecordV1, AgentOperationCasError, AgentOperationReservationV1,
    AgentOutcomeRecoveryTokenV1, AgentOutcomeStoreTransitionV1, AgentProvisioningV1,
    AgentRecoveredOperationV1, AgentRecoveredOutcomeCommitV1, AgentRecoveredReservationV1,
    AgentReducerError, AgentReservationDispositionV1, AgentReservationRecoveryTokenV1,
    AgentReservationStoreTransitionV1, AuthenticatedRecoveredAgentOutcomeV1, GuestAgentReducerV1,
    agent_handshake_signing_message_v1, validate_agent_checkpoint_history_v1,
};

use aos_sandbox_core::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::journal::{
    Journal, JournalError, JournalRecord, JournalTransaction, ProtectedJournalAuthority,
    RecordNamespace,
};

const OWNER_KEY: &[u8] = b"agent-durable-owner-v1";
const CHECKPOINT_KEY: &[u8] = b"agent-checkpoint-current-v1";
const SESSION_KEY: &[u8] = b"agent-session-current-v1";
const OPERATION_PREFIX: u8 = b'o';
const HEAD_PREFIX: u8 = b'h';
const OPERATION_MAGIC: &[u8; 8] = b"AOSAGO02";
const SESSION_MAGIC: &[u8; 8] = b"AOSAGS01";
const MAXIMUM_AGENT_STORE_RECORDS: usize = 16_384;

/// Owns a dedicated protected journal for dormant agent durable state.
pub(crate) struct DormantJournalAgentStoreV1<'journal> {
    authority: ProtectedJournalAuthority<'journal>,
    store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    agent_public_key: [u8; 32],
}

/// Owns one canonical checkpoint authenticated by the concrete protected journal.
pub struct AuthenticatedJournalAgentCheckpointV1 {
    checkpoint: AgentDurableCheckpointV1,
    store_sequence: u64,
    provenance: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
}

impl AuthenticatedJournalAgentCheckpointV1 {
    /// Returns the exact protected store sequence.
    #[must_use]
    pub const fn store_sequence(&self) -> u64 {
        self.store_sequence
    }

    /// Returns the concrete protected-journal provenance commitment.
    #[must_use]
    pub const fn provenance(&self) -> ObjectDigest {
        self.provenance
    }

    /// Returns the protected recovery key identity bound to the checkpoint.
    #[must_use]
    pub const fn recovery_authority_binding(&self) -> ObjectDigest {
        self.recovery_authority_binding
    }

    /// Consumes authenticated checkpoint authority to restore the reducer.
    ///
    /// Any later checkpoint remains a non-authoritative candidate until this
    /// store independently replays the complete retained operation graph.
    ///
    /// # Errors
    ///
    /// Returns [`AgentReducerError`] when provisioning or retained canonical
    /// reducer state does not match the protected checkpoint.
    pub(super) fn restore(
        self,
        provisioning: AgentProvisioningV1,
    ) -> Result<GuestAgentReducerV1, AgentReducerError> {
        if provisioning.recovery_authority_binding() != self.recovery_authority_binding {
            return Err(AgentReducerError::CheckpointProvisioningMismatch);
        }
        GuestAgentReducerV1::restore_checkpoint(provisioning, self.checkpoint)
    }
}

impl<'journal> DormantJournalAgentStoreV1<'journal> {
    /// Initializes an empty protected journal for agent durable state.
    ///
    /// # Errors
    ///
    /// Returns [`JournalAgentStoreError`] for a zero store/recovery binding,
    /// nonempty state, unavailable protection, preflight failure, or ambiguous
    /// durability.
    pub(crate) fn initialize(
        journal: &'journal mut Journal,
        store_binding: ObjectDigest,
        recovery_authority_binding: ObjectDigest,
        agent_public_key: [u8; 32],
    ) -> Result<Self, JournalAgentStoreError> {
        if store_binding.as_bytes() == &[0; 32]
            || recovery_authority_binding.as_bytes() == &[0; 32]
            || agent_public_key == [0; 32]
        {
            return Err(JournalAgentStoreError::InvalidBinding);
        }
        let mut authority = journal.claim_protected_authority(RecordNamespace::Effect)?;
        if !authority.is_materialized_empty()? {
            return Err(JournalAgentStoreError::ForeignStore);
        }
        let transaction = JournalTransaction::new(
            transaction_id(b"agent-owner", store_binding),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                OWNER_KEY.to_vec(),
                owner_value(store_binding, recovery_authority_binding),
            )],
        )?;
        let preflight = authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        authority.commit(&transaction)?;
        Ok(Self {
            authority,
            store_binding,
            recovery_authority_binding,
            agent_public_key,
        })
    }

    /// Reopens a previously initialized dedicated agent journal.
    ///
    /// # Errors
    ///
    /// Returns [`JournalAgentStoreError`] for a zero/foreign store or recovery
    /// binding, foreign records, corrupt ownership, or unavailable protected
    /// state.
    pub(crate) fn claim(
        journal: &'journal mut Journal,
        store_binding: ObjectDigest,
        recovery_authority_binding: ObjectDigest,
        agent_public_key: [u8; 32],
    ) -> Result<Self, JournalAgentStoreError> {
        if store_binding.as_bytes() == &[0; 32]
            || recovery_authority_binding.as_bytes() == &[0; 32]
            || agent_public_key == [0; 32]
        {
            return Err(JournalAgentStoreError::InvalidBinding);
        }
        let authority = journal.claim_protected_authority(RecordNamespace::Effect)?;
        let expected_owner = owner_value(store_binding, recovery_authority_binding);
        validate_agent_store_replay(
            &authority,
            &expected_owner,
            store_binding,
            recovery_authority_binding,
            agent_public_key,
        )?;
        Ok(Self {
            authority,
            store_binding,
            recovery_authority_binding,
            agent_public_key,
        })
    }

    /// Returns the sequence a one-record checkpoint commit must encode.
    ///
    /// # Errors
    ///
    /// Returns [`JournalAgentStoreError`] when protected state is unavailable
    /// or the journal sequence cannot advance.
    pub(super) fn next_checkpoint_sequence(&self) -> Result<u64, JournalAgentStoreError> {
        self.authority
            .snapshot()?
            .sequence()
            .checked_add(2)
            .ok_or(JournalAgentStoreError::SequenceExhausted)
    }

    pub(super) fn next_handshake_checkpoint_sequence(&self) -> Result<u64, JournalAgentStoreError> {
        self.authority
            .snapshot()?
            .sequence()
            .checked_add(3)
            .ok_or(JournalAgentStoreError::SequenceExhausted)
    }

    fn commit_records(&mut self, transaction: JournalTransaction) -> Result<u64, JournalError> {
        let preflight = self
            .authority
            .preflight_transactions(std::slice::from_ref(&transaction))?;
        self.authority
            .validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;
        self.authority
            .commit(&transaction)
            .map(|result| result.commit_sequence)
    }

    fn load_operation(
        &self,
        session: AgentSessionBindingV1,
        sequence: AgentOperationSequenceV1,
    ) -> Result<Option<StoredAgentOperationV1>, AgentOperationCasError> {
        self.authority
            .get(&operation_key(session, sequence))
            .map_err(map_cas_journal_error)?
            .map(decode_operation)
            .transpose()
    }

    pub(super) fn load_uncheckpointed_reservation(
        &self,
    ) -> Result<
        Option<(AgentOperationRequestV1, AgentOperationReservationV1)>,
        AgentOperationCasError,
    > {
        let checkpoint = self
            .authority
            .get(CHECKPOINT_KEY)
            .map_err(map_cas_journal_error)?
            .ok_or(AgentOperationCasError::InvalidReceipt)
            .and_then(|bytes| {
                decode_checkpoint_v1(bytes).map_err(|_| AgentOperationCasError::InvalidReceipt)
            })?;
        let session_record = self
            .authority
            .get(SESSION_KEY)
            .map_err(map_cas_journal_error)?
            .ok_or(AgentOperationCasError::InvalidReceipt)
            .and_then(|bytes| {
                decode_session_record(bytes).map_err(|_| AgentOperationCasError::InvalidReceipt)
            })?;
        validate_session_record(&session_record, &self.agent_public_key)
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
        let classification = validate_checkpoint_projection(
            &self.authority,
            &checkpoint,
            self.store_binding,
            self.recovery_authority_binding,
            Some(&session_record),
        )
        .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
        let AgentCheckpointProjectionV1::ReservationAhead {
            session,
            sequence,
            request_commitment,
            store_commitment,
        } = classification
        else {
            return Ok(None);
        };
        let stored = self
            .load_operation(session, sequence)?
            .ok_or(AgentOperationCasError::InvalidReceipt)?;
        if stored.phase != StoredOperationPhase::Reserved || stored.outcome.is_some() {
            return Err(AgentOperationCasError::Equivocation);
        }
        if stored.request_commitment != request_commitment
            || stored.store_commitment != store_commitment
            || stored.request.session() != session
            || stored.request.sequence() != sequence
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        let reservation = AgentOperationReservationV1::new(
            stored.session,
            stored.sequence,
            stored.operation,
            stored.request_commitment,
            stored.store_commitment,
            AgentReservationDispositionV1::ExactReplay,
        )?;
        Ok(Some((stored.request, reservation)))
    }

    fn validate_head_for_reservation(
        &self,
        session: AgentSessionBindingV1,
        expected: AgentOperationSequenceV1,
    ) -> Result<(), AgentOperationCasError> {
        let Some(bytes) = self
            .authority
            .get(&head_key(session))
            .map_err(map_cas_journal_error)?
        else {
            return if expected.get() == 1 {
                Ok(())
            } else {
                Err(AgentOperationCasError::SequenceConflict)
            };
        };
        if bytes.len() != 56 {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        let previous_sequence = AgentOperationSequenceV1::new(u64::from_be_bytes(
            bytes[..8]
                .try_into()
                .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
        ))
        .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
        let previous_operation = AgentOperationIdV1::new(
            bytes[8..24]
                .try_into()
                .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
        )
        .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
        let previous_request = ObjectDigest::from_bytes(
            bytes[24..56]
                .try_into()
                .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
        );
        let previous = self
            .load_operation(session, previous_sequence)?
            .ok_or(AgentOperationCasError::InvalidReceipt)?;
        if previous.phase != StoredOperationPhase::Complete
            || previous.operation != previous_operation
            || previous.request_commitment != previous_request
        {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        if previous_sequence
            .checked_next()
            .map_err(|_| AgentOperationCasError::SequenceConflict)?
            != expected
        {
            return Err(AgentOperationCasError::SequenceConflict);
        }
        Ok(())
    }

    fn validate_exact_head(
        &self,
        session: AgentSessionBindingV1,
        sequence: AgentOperationSequenceV1,
        operation: AgentOperationIdV1,
        request: ObjectDigest,
    ) -> Result<(), AgentOperationCasError> {
        let bytes = self
            .authority
            .get(&head_key(session))
            .map_err(map_cas_journal_error)?
            .ok_or(AgentOperationCasError::InvalidReceipt)?;
        if bytes != encode_head(sequence, operation, request) {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        let stored = self
            .load_operation(session, sequence)?
            .ok_or(AgentOperationCasError::InvalidReceipt)?;
        if stored.operation != operation
            || stored.request_commitment != request
            || stored.session != session
            || stored.sequence != sequence
        {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        Ok(())
    }

    fn commit_bound_outcome(
        &mut self,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
        recovery_provenance: Option<ObjectDigest>,
    ) -> Result<AgentOutcomeStoreTransitionV1, AgentOperationCasError> {
        self.validate_exact_head(
            reservation.session(),
            reservation.sequence(),
            reservation.operation_id(),
            reservation.request_commitment(),
        )?;
        if recovery_provenance.is_some_and(|value| value.as_bytes() == &[0; 32]) {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        let stored = self
            .load_operation(reservation.session(), reservation.sequence())?
            .ok_or(AgentOperationCasError::InvalidReceipt)?;
        if stored.operation != reservation.operation_id()
            || stored.request_commitment != reservation.request_commitment()
            || stored.store_commitment != reservation.store_commitment()
            || outcome.session() != reservation.session()
            || outcome.sequence() != reservation.sequence()
            || outcome.operation_id() != reservation.operation_id()
            || outcome.request_commitment() != reservation.request_commitment()
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        if let Some(existing) = stored.outcome.as_ref() {
            return if existing == outcome && stored.recovery_provenance == recovery_provenance {
                Ok(AgentOutcomeStoreTransitionV1::Committed(
                    existing.outcome_commitment(),
                ))
            } else {
                Err(AgentOperationCasError::Equivocation)
            };
        }
        let predecessor_commitment = operation_state_commitment(&encode_operation(&stored));
        let recovery_binding = outcome_recovery_binding(
            self.store_binding,
            self.recovery_authority_binding,
            reservation,
            outcome.outcome_commitment(),
            predecessor_commitment,
        );
        let completed = StoredAgentOperationV1 {
            phase: StoredOperationPhase::Complete,
            outcome: Some(outcome.clone()),
            recovery_provenance,
            ..stored
        };
        let transaction = JournalTransaction::new(
            transaction_id(b"agent-complete", outcome.outcome_commitment()),
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    operation_key(reservation.session(), reservation.sequence()),
                    encode_operation(&completed),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    head_key(reservation.session()),
                    encode_head(
                        reservation.sequence(),
                        reservation.operation_id(),
                        reservation.request_commitment(),
                    ),
                ),
            ],
        )
        .map_err(map_cas_journal_error)?;
        match self.commit_records(transaction) {
            Ok(_) => Ok(AgentOutcomeStoreTransitionV1::Committed(
                outcome.outcome_commitment(),
            )),
            Err(_) => Ok(AgentOutcomeStoreTransitionV1::RecoveryRequired {
                outcome_commitment: outcome.outcome_commitment(),
                predecessor_commitment,
                recovery_binding,
            }),
        }
    }
}

impl DormantJournalAgentStoreV1<'_> {
    pub(super) fn reserve_operation(
        &mut self,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentReservationStoreTransitionV1, AgentOperationCasError> {
        let session = request.session();
        let expected_sequence = request.sequence();
        let operation_id = request.operation_id();
        let request_commitment = request.request_commitment();
        if request_commitment.as_bytes() == &[0; 32] {
            return Err(AgentOperationCasError::InvalidReceipt);
        }
        if let Some(stored) = self.load_operation(session, expected_sequence)? {
            if stored.operation != operation_id
                || stored.request_commitment != request_commitment
                || stored.request != *request
            {
                return Err(AgentOperationCasError::Equivocation);
            }
            return AgentOperationReservationV1::new(
                session,
                expected_sequence,
                operation_id,
                request_commitment,
                stored.store_commitment,
                AgentReservationDispositionV1::ExactReplay,
            )
            .map(AgentReservationStoreTransitionV1::Committed);
        }
        self.validate_head_for_reservation(session, expected_sequence)?;
        let predecessor_commitment = head_state_commitment(
            self.authority
                .get(&head_key(session))
                .map_err(map_cas_journal_error)?,
        );
        let current = self
            .authority
            .snapshot()
            .map_err(map_cas_journal_error)?
            .sequence();
        let commit_sequence = current
            .checked_add(3)
            .ok_or(AgentOperationCasError::SequenceConflict)?;
        let store_commitment = reservation_commitment(
            self.store_binding,
            self.recovery_authority_binding,
            session,
            expected_sequence,
            operation_id,
            request_commitment,
            commit_sequence,
        );
        let recovery_binding = reservation_recovery_binding(
            self.store_binding,
            self.recovery_authority_binding,
            session,
            expected_sequence,
            operation_id,
            request_commitment,
            store_commitment,
            predecessor_commitment,
        );
        let stored = StoredAgentOperationV1 {
            phase: StoredOperationPhase::Reserved,
            session,
            sequence: expected_sequence,
            operation: operation_id,
            request_commitment,
            store_commitment,
            reservation_sequence: commit_sequence,
            request: request.clone(),
            outcome: None,
            recovery_provenance: None,
        };
        let transaction = JournalTransaction::new(
            transaction_id(b"agent-reserve", store_commitment),
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    operation_key(session, expected_sequence),
                    encode_operation(&stored),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    head_key(session),
                    encode_head(expected_sequence, operation_id, request_commitment),
                ),
            ],
        )
        .map_err(map_cas_journal_error)?;
        match self.commit_records(transaction) {
            Ok(sequence) if sequence == commit_sequence => AgentOperationReservationV1::new(
                session,
                expected_sequence,
                operation_id,
                request_commitment,
                store_commitment,
                AgentReservationDispositionV1::Created,
            )
            .map(AgentReservationStoreTransitionV1::Committed),
            Ok(_) => Err(AgentOperationCasError::InvalidReceipt),
            Err(_) => Ok(AgentReservationStoreTransitionV1::RecoveryRequired {
                store_commitment,
                predecessor_commitment,
                recovery_binding,
            }),
        }
    }

    pub(super) fn commit_operation_outcome(
        &mut self,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<AgentOutcomeStoreTransitionV1, AgentOperationCasError> {
        self.commit_bound_outcome(reservation, outcome, None)
    }
}

impl DormantJournalAgentStoreV1<'_> {
    pub(super) fn recover_reservation(
        &mut self,
        token: &AgentReservationRecoveryTokenV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredReservationV1, AgentOperationCasError> {
        if request.session() != token.session()
            || request.sequence() != token.sequence()
            || request.operation_id() != token.operation_id()
            || request.request_commitment() != token.request_commitment()
            || token.recovery_binding()
                != reservation_recovery_binding(
                    self.store_binding,
                    self.recovery_authority_binding,
                    token.session(),
                    token.sequence(),
                    token.operation_id(),
                    token.request_commitment(),
                    token.store_commitment(),
                    token.predecessor_commitment(),
                )
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        match self.load_operation(token.session(), token.sequence())? {
            Some(stored)
                if stored.operation == token.operation_id()
                    && stored.request_commitment == token.request_commitment()
                    && stored.store_commitment == token.store_commitment() =>
            {
                self.validate_exact_head(
                    token.session(),
                    token.sequence(),
                    token.operation_id(),
                    token.request_commitment(),
                )?;
                AgentOperationReservationV1::new(
                    token.session(),
                    token.sequence(),
                    token.operation_id(),
                    token.request_commitment(),
                    token.store_commitment(),
                    AgentReservationDispositionV1::ExactReplay,
                )
                .map(AgentRecoveredReservationV1::Committed)
            }
            Some(_) => Err(AgentOperationCasError::Equivocation),
            None => {
                let current = self
                    .authority
                    .get(&head_key(token.session()))
                    .map_err(map_cas_journal_error)?;
                if head_state_commitment(current) != token.predecessor_commitment() {
                    return Err(AgentOperationCasError::Equivocation);
                }
                Ok(AgentRecoveredReservationV1::Absent)
            }
        }
    }

    pub(super) fn recover_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
    ) -> Result<AgentRecoveredOperationV1, AgentOperationCasError> {
        if request.session() != reservation.session()
            || request.sequence() != reservation.sequence()
            || request.operation_id() != reservation.operation_id()
            || request.request_commitment() != reservation.request_commitment()
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        let Some(stored) = self.load_operation(reservation.session(), reservation.sequence())?
        else {
            return Ok(AgentRecoveredOperationV1::Absent);
        };
        if stored.operation != reservation.operation_id()
            || stored.request_commitment != reservation.request_commitment()
            || stored.store_commitment != reservation.store_commitment()
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        match stored.outcome {
            Some(outcome) => Ok(AgentRecoveredOperationV1::Completed(outcome)),
            None => Ok(AgentRecoveredOperationV1::Reserved),
        }
    }

    pub(super) fn recover_outcome_commit(
        &mut self,
        token: &AgentOutcomeRecoveryTokenV1,
        reservation: &AgentOperationReservationV1,
        outcome: &AgentExecutionOutcomeV1,
    ) -> Result<AgentRecoveredOutcomeCommitV1, AgentOperationCasError> {
        if token.session() != reservation.session()
            || token.sequence() != reservation.sequence()
            || token.operation_id() != reservation.operation_id()
            || token.request_commitment() != reservation.request_commitment()
            || token.store_commitment() != reservation.store_commitment()
            || token.outcome_commitment() != outcome.outcome_commitment()
            || token.recovery_binding()
                != outcome_recovery_binding(
                    self.store_binding,
                    self.recovery_authority_binding,
                    reservation,
                    token.outcome_commitment(),
                    token.predecessor_commitment(),
                )
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        let stored = self
            .load_operation(reservation.session(), reservation.sequence())?
            .ok_or(AgentOperationCasError::Equivocation)?;
        if stored.operation != reservation.operation_id()
            || stored.request_commitment != reservation.request_commitment()
            || stored.store_commitment != reservation.store_commitment()
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        match stored.outcome.as_ref() {
            Some(committed) if committed == outcome => Ok(
                AgentRecoveredOutcomeCommitV1::Committed(committed.outcome_commitment()),
            ),
            Some(_) => Err(AgentOperationCasError::Equivocation),
            None if operation_state_commitment(&encode_operation(&stored))
                == token.predecessor_commitment() =>
            {
                Ok(AgentRecoveredOutcomeCommitV1::Absent)
            }
            None => Err(AgentOperationCasError::Equivocation),
        }
    }

    pub(super) fn resolve_reserved_operation(
        &mut self,
        reservation: &AgentOperationReservationV1,
        request: &AgentOperationRequestV1,
        authenticated: AuthenticatedRecoveredAgentOutcomeV1,
    ) -> Result<AgentOutcomeStoreTransitionV1, AgentOperationCasError> {
        if request.session() != reservation.session()
            || request.sequence() != reservation.sequence()
            || request.operation_id() != reservation.operation_id()
            || request.request_commitment() != reservation.request_commitment()
            || authenticated.provenance().as_bytes() == &[0; 32]
            || authenticated.authority_binding() != self.recovery_authority_binding
        {
            return Err(AgentOperationCasError::Equivocation);
        }
        let stored = self
            .load_operation(reservation.session(), reservation.sequence())?
            .ok_or(AgentOperationCasError::InvalidReceipt)?;
        if stored.phase != StoredOperationPhase::Reserved || stored.outcome.is_some() {
            return Err(AgentOperationCasError::Equivocation);
        }
        self.commit_bound_outcome(
            reservation,
            authenticated.outcome(),
            Some(authenticated.provenance()),
        )
    }
}

impl DormantJournalAgentStoreV1<'_> {
    pub(super) fn commit_handshake_checkpoint(
        &mut self,
        request: &AgentHandshakeRequestV1,
        response: &AgentHandshakeResponseV1,
        candidate: &AgentCheckpointCandidateV1,
    ) -> Result<AuthenticatedJournalAgentCheckpointV1, AgentCheckpointError> {
        let session = StoredAgentSessionV1 {
            request: request.clone(),
            response: response.clone(),
        };
        validate_session_record(&session, &self.agent_public_key)
            .map_err(|_| AgentCheckpointError::Unauthenticated)?;
        validate_checkpoint_projection(
            &self.authority,
            candidate.checkpoint(),
            self.store_binding,
            self.recovery_authority_binding,
            Some(&session),
        )
        .map_err(|_| AgentCheckpointError::Unauthenticated)?;
        let expected = self
            .next_handshake_checkpoint_sequence()
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        if candidate.checkpoint().sequence() != expected {
            return Err(AgentCheckpointError::Unauthenticated);
        }
        let transaction = JournalTransaction::new(
            transaction_id(
                b"agent-handshake-checkpoint",
                candidate.checkpoint().checkpoint_commitment(),
            ),
            vec![
                JournalRecord::put(
                    RecordNamespace::Effect,
                    SESSION_KEY.to_vec(),
                    encode_session_record(&session),
                ),
                JournalRecord::put(
                    RecordNamespace::Effect,
                    CHECKPOINT_KEY.to_vec(),
                    candidate.checkpoint().as_bytes().to_vec(),
                ),
            ],
        )
        .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        let committed = self
            .commit_records(transaction)
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        if committed != candidate.checkpoint().sequence() {
            return Err(AgentCheckpointError::Unauthenticated);
        }
        Ok(authenticated_checkpoint(
            candidate.checkpoint().clone(),
            committed,
            self.store_binding,
            self.recovery_authority_binding,
        ))
    }

    /// Commits a canonical checkpoint and returns concrete protected authority.
    ///
    /// # Errors
    ///
    /// Returns [`AgentCheckpointError`] for sequence mismatch, conflict,
    /// unavailable protected storage, or ambiguous durability.
    pub(super) fn commit_checkpoint(
        &mut self,
        candidate: &AgentCheckpointCandidateV1,
    ) -> Result<AuthenticatedJournalAgentCheckpointV1, AgentCheckpointError> {
        let checkpoint = candidate.checkpoint();
        validate_checkpoint_projection(
            &self.authority,
            checkpoint,
            self.store_binding,
            self.recovery_authority_binding,
            None,
        )
        .map_err(|_| AgentCheckpointError::Unauthenticated)?;
        if let Some(existing) = self
            .authority
            .get(CHECKPOINT_KEY)
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?
        {
            let existing = decode_checkpoint_v1(existing)?;
            if existing.sequence() == checkpoint.sequence()
                && existing.checkpoint_commitment() == checkpoint.checkpoint_commitment()
            {
                return Ok(AuthenticatedJournalAgentCheckpointV1 {
                    checkpoint: existing.clone(),
                    store_sequence: existing.sequence(),
                    provenance: checkpoint_provenance(
                        self.store_binding,
                        self.recovery_authority_binding,
                        &existing,
                    ),
                    recovery_authority_binding: self.recovery_authority_binding,
                });
            }
            if existing.sequence() >= checkpoint.sequence() {
                return Err(AgentCheckpointError::StoreUnavailable);
            }
        }
        let expected = self
            .next_checkpoint_sequence()
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        if checkpoint.sequence() != expected {
            return Err(AgentCheckpointError::Unauthenticated);
        }
        let transaction = JournalTransaction::new(
            transaction_id(b"agent-checkpoint", checkpoint.checkpoint_commitment()),
            vec![JournalRecord::put(
                RecordNamespace::Effect,
                CHECKPOINT_KEY.to_vec(),
                checkpoint.as_bytes().to_vec(),
            )],
        )
        .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        let committed = self
            .commit_records(transaction)
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?;
        if committed != checkpoint.sequence() {
            return Err(AgentCheckpointError::Unauthenticated);
        }
        Ok(AuthenticatedJournalAgentCheckpointV1 {
            checkpoint: checkpoint.clone(),
            store_sequence: committed,
            provenance: checkpoint_provenance(
                self.store_binding,
                self.recovery_authority_binding,
                checkpoint,
            ),
            recovery_authority_binding: self.recovery_authority_binding,
        })
    }

    /// Loads the newest checkpoint through concrete protected-journal authority.
    ///
    /// # Errors
    ///
    /// Returns [`AgentCheckpointError`] for malformed, unavailable, rolled-back,
    /// or unauthenticated protected state.
    pub(super) fn load_checkpoint(
        &mut self,
    ) -> Result<Option<AuthenticatedJournalAgentCheckpointV1>, AgentCheckpointError> {
        let Some(bytes) = self
            .authority
            .get(CHECKPOINT_KEY)
            .map_err(|_| AgentCheckpointError::StoreUnavailable)?
        else {
            return Ok(None);
        };
        let checkpoint = decode_checkpoint_v1(bytes)?;
        Ok(Some(AuthenticatedJournalAgentCheckpointV1 {
            store_sequence: checkpoint.sequence(),
            provenance: checkpoint_provenance(
                self.store_binding,
                self.recovery_authority_binding,
                &checkpoint,
            ),
            recovery_authority_binding: self.recovery_authority_binding,
            checkpoint,
        }))
    }
}

struct StoredAgentSessionV1 {
    request: AgentHandshakeRequestV1,
    response: AgentHandshakeResponseV1,
}

fn encode_session_record(session: &StoredAgentSessionV1) -> Vec<u8> {
    let request = encode_frame_v1(&AgentFrameV1::HandshakeRequest(session.request.clone()));
    let response = encode_frame_v1(&AgentFrameV1::HandshakeResponse(session.response.clone()));
    let mut bytes = Vec::with_capacity(8 + 4 + request.len() + 4 + response.len());
    bytes.extend_from_slice(SESSION_MAGIC);
    bytes.extend_from_slice(&(request.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&request);
    bytes.extend_from_slice(&(response.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&response);
    bytes
}

fn decode_session_record(bytes: &[u8]) -> Result<StoredAgentSessionV1, JournalAgentStoreError> {
    if bytes.len() < 16 || bytes.get(..8) != Some(SESSION_MAGIC.as_slice()) {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    let request_length = usize::try_from(u32::from_be_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?,
    ))
    .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
    let request_end = 12_usize
        .checked_add(request_length)
        .ok_or(JournalAgentStoreError::CorruptRecord)?;
    let response_length_end = request_end
        .checked_add(4)
        .ok_or(JournalAgentStoreError::CorruptRecord)?;
    if request_length == 0 || response_length_end > bytes.len() {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    let AgentFrameV1::HandshakeRequest(request) = decode_frame_v1(&bytes[12..request_end])
        .map_err(|_| JournalAgentStoreError::CorruptRecord)?
    else {
        return Err(JournalAgentStoreError::CorruptRecord);
    };
    let response_length = usize::try_from(u32::from_be_bytes(
        bytes[request_end..response_length_end]
            .try_into()
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?,
    ))
    .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
    let response_end = response_length_end
        .checked_add(response_length)
        .ok_or(JournalAgentStoreError::CorruptRecord)?;
    if response_length == 0 || response_end != bytes.len() {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    let AgentFrameV1::HandshakeResponse(response) =
        decode_frame_v1(&bytes[response_length_end..response_end])
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?
    else {
        return Err(JournalAgentStoreError::CorruptRecord);
    };
    let session = StoredAgentSessionV1 { request, response };
    if encode_session_record(&session) != bytes {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    Ok(session)
}

fn validate_session_record(
    session: &StoredAgentSessionV1,
    agent_public_key: &[u8; 32],
) -> Result<(), JournalAgentStoreError> {
    let binding =
        AgentSessionBindingV1::derive(&session.request, session.response.agent_instance())
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
    if binding != session.response.session_binding() {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    let signing_message = agent_handshake_signing_message_v1(
        &session.request,
        binding,
        session.response.agent_instance(),
        session.response.features(),
    );
    let verifying_key = VerifyingKey::from_bytes(agent_public_key)
        .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
    verifying_key
        .verify_strict(
            &signing_message,
            &Signature::from_bytes(session.response.challenge_signature()),
        )
        .map_err(|_| JournalAgentStoreError::CorruptRecord)
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StoredOperationPhase {
    Reserved,
    Complete,
}

struct StoredAgentOperationV1 {
    phase: StoredOperationPhase,
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation: AgentOperationIdV1,
    request_commitment: ObjectDigest,
    store_commitment: ObjectDigest,
    reservation_sequence: u64,
    request: AgentOperationRequestV1,
    outcome: Option<AgentExecutionOutcomeV1>,
    recovery_provenance: Option<ObjectDigest>,
}

fn encode_operation(operation: &StoredAgentOperationV1) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(OPERATION_MAGIC);
    bytes.push(match operation.phase {
        StoredOperationPhase::Reserved => 1,
        StoredOperationPhase::Complete => 2,
    });
    bytes.extend_from_slice(operation.session.digest().as_bytes());
    bytes.extend_from_slice(&operation.sequence.get().to_be_bytes());
    bytes.extend_from_slice(operation.operation.as_bytes());
    bytes.extend_from_slice(operation.request_commitment.as_bytes());
    bytes.extend_from_slice(operation.store_commitment.as_bytes());
    bytes.extend_from_slice(&operation.reservation_sequence.to_be_bytes());
    match operation.recovery_provenance {
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 32]);
        }
        Some(provenance) => {
            bytes.push(1);
            bytes.extend_from_slice(provenance.as_bytes());
        }
    }
    let request_frame = encode_frame_v1(&AgentFrameV1::OperationRequest(operation.request.clone()));
    bytes.extend_from_slice(&(request_frame.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&request_frame);
    match &operation.outcome {
        None => bytes.extend_from_slice(&0_u32.to_be_bytes()),
        Some(outcome) => {
            let frame = encode_frame_v1(&AgentFrameV1::OperationOutcome(outcome.clone()));
            bytes.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            bytes.extend_from_slice(&frame);
        }
    }
    bytes
}

fn decode_operation(bytes: &[u8]) -> Result<StoredAgentOperationV1, AgentOperationCasError> {
    const PREFIX: usize = 8 + 1 + 32 + 8 + 16 + 32 + 32 + 8 + 1 + 32 + 4;
    if bytes.len() < PREFIX + 4 || bytes.get(..8) != Some(OPERATION_MAGIC.as_slice()) {
        return Err(AgentOperationCasError::InvalidReceipt);
    }
    let phase = match bytes[8] {
        1 => StoredOperationPhase::Reserved,
        2 => StoredOperationPhase::Complete,
        _ => return Err(AgentOperationCasError::InvalidReceipt),
    };
    let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(
        bytes[9..41]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    ))
    .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
    let sequence = AgentOperationSequenceV1::new(u64::from_be_bytes(
        bytes[41..49]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    ))
    .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
    let operation = AgentOperationIdV1::new(
        bytes[49..65]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    )
    .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
    let request_commitment = ObjectDigest::from_bytes(
        bytes[65..97]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    );
    let store_commitment = ObjectDigest::from_bytes(
        bytes[97..129]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    );
    let reservation_sequence = u64::from_be_bytes(
        bytes[129..137]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    );
    let recovery_provenance = match bytes[137] {
        0 if bytes[138..170] == [0; 32] => None,
        1 => Some(ObjectDigest::from_bytes(
            bytes[138..170]
                .try_into()
                .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
        )),
        _ => return Err(AgentOperationCasError::InvalidReceipt),
    };
    let request_length = usize::try_from(u32::from_be_bytes(
        bytes[170..174]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    ))
    .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
    let request_end = PREFIX
        .checked_add(request_length)
        .ok_or(AgentOperationCasError::InvalidReceipt)?;
    let outcome_length_end = request_end
        .checked_add(4)
        .ok_or(AgentOperationCasError::InvalidReceipt)?;
    if request_length == 0 || outcome_length_end > bytes.len() {
        return Err(AgentOperationCasError::InvalidReceipt);
    }
    let AgentFrameV1::OperationRequest(request) = decode_frame_v1(&bytes[PREFIX..request_end])
        .map_err(|_| AgentOperationCasError::InvalidReceipt)?
    else {
        return Err(AgentOperationCasError::InvalidReceipt);
    };
    let outcome_length = usize::try_from(u32::from_be_bytes(
        bytes[request_end..outcome_length_end]
            .try_into()
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?,
    ))
    .map_err(|_| AgentOperationCasError::InvalidReceipt)?;
    if bytes.len() != outcome_length_end.saturating_add(outcome_length) {
        return Err(AgentOperationCasError::InvalidReceipt);
    }
    let outcome = if outcome_length == 0 {
        None
    } else {
        let AgentFrameV1::OperationOutcome(outcome) = decode_frame_v1(&bytes[outcome_length_end..])
            .map_err(|_| AgentOperationCasError::InvalidReceipt)?
        else {
            return Err(AgentOperationCasError::InvalidReceipt);
        };
        Some(outcome)
    };
    if (phase == StoredOperationPhase::Complete) != outcome.is_some()
        || (phase == StoredOperationPhase::Reserved && recovery_provenance.is_some())
        || request_commitment.as_bytes() == &[0; 32]
        || store_commitment.as_bytes() == &[0; 32]
        || reservation_sequence == 0
        || request.session() != session
        || request.sequence() != sequence
        || request.operation_id() != operation
        || request.request_commitment() != request_commitment
        || recovery_provenance.is_some_and(|value| value.as_bytes() == &[0; 32])
        || outcome.as_ref().is_some_and(|value| {
            value.session() != session
                || value.sequence() != sequence
                || value.operation_id() != operation
                || value.request_commitment() != request_commitment
        })
    {
        return Err(AgentOperationCasError::InvalidReceipt);
    }
    Ok(StoredAgentOperationV1 {
        phase,
        session,
        sequence,
        operation,
        request_commitment,
        store_commitment,
        reservation_sequence,
        request,
        outcome,
        recovery_provenance,
    })
}

fn operation_key(session: AgentSessionBindingV1, sequence: AgentOperationSequenceV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(41);
    key.push(OPERATION_PREFIX);
    key.extend_from_slice(session.digest().as_bytes());
    key.extend_from_slice(&sequence.get().to_be_bytes());
    key
}

fn head_key(session: AgentSessionBindingV1) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(HEAD_PREFIX);
    key.extend_from_slice(session.digest().as_bytes());
    key
}

fn encode_head(
    sequence: AgentOperationSequenceV1,
    operation: AgentOperationIdV1,
    request: ObjectDigest,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(56);
    bytes.extend_from_slice(&sequence.get().to_be_bytes());
    bytes.extend_from_slice(operation.as_bytes());
    bytes.extend_from_slice(request.as_bytes());
    bytes
}

fn owned_key(key: &[u8]) -> bool {
    key == OWNER_KEY
        || key == CHECKPOINT_KEY
        || key == SESSION_KEY
        || matches!(key, [OPERATION_PREFIX, ..] if key.len() == 41)
        || matches!(key, [HEAD_PREFIX, ..] if key.len() == 33)
}

fn validate_agent_store_replay(
    authority: &ProtectedJournalAuthority<'_>,
    expected_owner: &[u8],
    store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    agent_public_key: [u8; 32],
) -> Result<(), JournalAgentStoreError> {
    let protected_sequence = authority.snapshot()?.sequence();
    let mut owner_seen = false;
    let mut checkpoint = None;
    let mut session = None;
    let mut operations = BTreeMap::new();
    let mut heads = BTreeMap::new();
    let mut operation_ids = BTreeSet::new();
    let mut store_commitments = BTreeSet::new();
    let mut reservation_sequences = BTreeSet::new();
    let mut outcome_commitments = BTreeSet::new();
    let mut record_count = 0_usize;

    for (key, value) in authority.records()? {
        record_count = record_count
            .checked_add(1)
            .ok_or(JournalAgentStoreError::CorruptRecord)?;
        if record_count > MAXIMUM_AGENT_STORE_RECORDS || !owned_key(key) {
            return Err(JournalAgentStoreError::ForeignStore);
        }
        if key == OWNER_KEY {
            if owner_seen || value != expected_owner {
                return Err(JournalAgentStoreError::ForeignStore);
            }
            owner_seen = true;
            continue;
        }
        if key == CHECKPOINT_KEY {
            if checkpoint.is_some() {
                return Err(JournalAgentStoreError::CorruptRecord);
            }
            let decoded =
                decode_checkpoint_v1(value).map_err(|_| JournalAgentStoreError::CorruptRecord)?;
            if decoded.as_bytes() != value
                || decoded.sequence() == 0
                || decoded.sequence() > protected_sequence
            {
                return Err(JournalAgentStoreError::CorruptRecord);
            }
            checkpoint = Some(decoded);
            continue;
        }
        if key == SESSION_KEY {
            if session.is_some() {
                return Err(JournalAgentStoreError::CorruptRecord);
            }
            let decoded = decode_session_record(value)?;
            validate_session_record(&decoded, &agent_public_key)?;
            session = Some(decoded);
            continue;
        }

        match key.first().copied() {
            Some(OPERATION_PREFIX) if key.len() == 41 => {
                let stored =
                    decode_operation(value).map_err(|_| JournalAgentStoreError::CorruptRecord)?;
                if operation_key(stored.session, stored.sequence) != key
                    || encode_operation(&stored) != value
                    || stored.reservation_sequence > protected_sequence
                    || stored.store_commitment
                        != reservation_commitment(
                            store_binding,
                            recovery_authority_binding,
                            stored.session,
                            stored.sequence,
                            stored.operation,
                            stored.request_commitment,
                            stored.reservation_sequence,
                        )
                    || !operation_ids.insert(*stored.operation.as_bytes())
                    || !store_commitments.insert(*stored.store_commitment.as_bytes())
                    || !reservation_sequences.insert(stored.reservation_sequence)
                    || stored.outcome.as_ref().is_some_and(|outcome| {
                        !outcome_commitments.insert(*outcome.outcome_commitment().as_bytes())
                    })
                {
                    return Err(JournalAgentStoreError::CorruptRecord);
                }
                let identity = (*stored.session.digest().as_bytes(), stored.sequence.get());
                if operations.insert(identity, stored).is_some() {
                    return Err(JournalAgentStoreError::CorruptRecord);
                }
            }
            Some(HEAD_PREFIX) if key.len() == 33 => {
                let session = AgentSessionBindingV1::from_digest(ObjectDigest::from_bytes(
                    key[1..33]
                        .try_into()
                        .map_err(|_| JournalAgentStoreError::CorruptRecord)?,
                ))
                .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
                let head = decode_head(value)?;
                if head_key(session) != key
                    || heads.insert(*session.digest().as_bytes(), head).is_some()
                {
                    return Err(JournalAgentStoreError::CorruptRecord);
                }
            }
            _ => return Err(JournalAgentStoreError::ForeignStore),
        }
    }
    if !owner_seen {
        return Err(JournalAgentStoreError::ForeignStore);
    }

    let mut operations_by_session: BTreeMap<[u8; 32], Vec<&StoredAgentOperationV1>> =
        BTreeMap::new();
    for ((session, _), operation) in &operations {
        operations_by_session
            .entry(*session)
            .or_default()
            .push(operation);
    }
    if operations_by_session.len() != heads.len() {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    for (session, session_operations) in operations_by_session {
        let head = heads
            .get(&session)
            .ok_or(JournalAgentStoreError::CorruptRecord)?;
        let operation_count = session_operations.len();
        for (index, operation) in session_operations.iter().enumerate() {
            let expected_sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(JournalAgentStoreError::CorruptRecord)?;
            if operation.sequence.get() != expected_sequence
                || (index + 1 != operation_count
                    && operation.phase != StoredOperationPhase::Complete)
            {
                return Err(JournalAgentStoreError::CorruptRecord);
            }
        }
        let latest = session_operations
            .last()
            .ok_or(JournalAgentStoreError::CorruptRecord)?;
        if head.sequence != latest.sequence
            || head.operation != latest.operation
            || head.request_commitment != latest.request_commitment
        {
            return Err(JournalAgentStoreError::CorruptRecord);
        }
    }
    if let Some(checkpoint) = checkpoint.as_ref() {
        validate_checkpoint_projection_from_operations(
            checkpoint,
            operations.values(),
            session.as_ref(),
            recovery_authority_binding,
        )?;
    } else if !operations.is_empty() {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    if checkpoint.is_some() != session.is_some() {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    Ok(())
}

fn validate_checkpoint_projection(
    authority: &ProtectedJournalAuthority<'_>,
    checkpoint: &AgentDurableCheckpointV1,
    store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    session_override: Option<&StoredAgentSessionV1>,
) -> Result<AgentCheckpointProjectionV1, JournalAgentStoreError> {
    let protected_sequence = authority.snapshot()?.sequence();
    let mut operations = Vec::new();
    let mut stored_session = None;
    for (key, value) in authority.records()? {
        if key == SESSION_KEY {
            stored_session = Some(decode_session_record(value)?);
            continue;
        }
        if matches!(key, [OPERATION_PREFIX, ..] if key.len() == 41) {
            let stored =
                decode_operation(value).map_err(|_| JournalAgentStoreError::CorruptRecord)?;
            if stored.reservation_sequence > protected_sequence
                || stored.store_commitment
                    != reservation_commitment(
                        store_binding,
                        recovery_authority_binding,
                        stored.session,
                        stored.sequence,
                        stored.operation,
                        stored.request_commitment,
                        stored.reservation_sequence,
                    )
            {
                return Err(JournalAgentStoreError::CorruptRecord);
            }
            operations.push(stored);
        }
    }
    let session = session_override.or(stored_session.as_ref());
    validate_checkpoint_projection_from_operations(
        checkpoint,
        operations.iter(),
        session,
        recovery_authority_binding,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AgentCheckpointProjectionV1 {
    Exact,
    ReservationAhead {
        session: AgentSessionBindingV1,
        sequence: AgentOperationSequenceV1,
        request_commitment: ObjectDigest,
        store_commitment: ObjectDigest,
    },
    TerminalAhead,
}

fn validate_checkpoint_projection_from_operations<'operation>(
    checkpoint: &AgentDurableCheckpointV1,
    operations: impl Iterator<Item = &'operation StoredAgentOperationV1>,
    authenticated_session: Option<&StoredAgentSessionV1>,
    recovery_authority_binding: ObjectDigest,
) -> Result<AgentCheckpointProjectionV1, JournalAgentStoreError> {
    let authenticated_binding =
        authenticated_session.map(|record| record.response.session_binding());
    let mut operations: Vec<_> = operations.collect();
    operations.sort_by_key(|operation| operation.reservation_sequence);
    let exact_rows: Vec<_> = operations
        .iter()
        .map(|operation| {
            AgentDurableHistoryRecordV1::new(
                &operation.request,
                operation.store_commitment,
                operation.outcome.as_ref(),
            )
        })
        .collect();
    if operations
        .iter()
        .all(|operation| operation.reservation_sequence < checkpoint.sequence())
        && validate_agent_checkpoint_history_v1(checkpoint, &exact_rows, authenticated_binding)
            .is_ok()
    {
        return Ok(AgentCheckpointProjectionV1::Exact);
    }

    // The only accepted lag is the single protected transition that can win
    // immediately before its matching checkpoint append.
    if let Some(latest) = operations.last() {
        if latest.outcome.is_some() {
            let reserved_rows: Vec<_> = operations
                .iter()
                .map(|operation| {
                    AgentDurableHistoryRecordV1::new(
                        &operation.request,
                        operation.store_commitment,
                        if std::ptr::eq(*operation, *latest) {
                            None
                        } else {
                            operation.outcome.as_ref()
                        },
                    )
                })
                .collect();
            if operations
                .iter()
                .all(|operation| operation.reservation_sequence < checkpoint.sequence())
                && validate_agent_checkpoint_history_v1(
                    checkpoint,
                    &reserved_rows,
                    authenticated_binding,
                )
                .is_ok()
            {
                return Ok(AgentCheckpointProjectionV1::TerminalAhead);
            }
        }
        let prior_rows: Vec<_> = operations[..operations.len() - 1]
            .iter()
            .map(|operation| {
                AgentDurableHistoryRecordV1::new(
                    &operation.request,
                    operation.store_commitment,
                    operation.outcome.as_ref(),
                )
            })
            .collect();
        let reservation_is_authenticated_successor = || {
            let session = authenticated_session.ok_or(JournalAgentStoreError::CorruptRecord)?;
            if latest.session != session.response.session_binding() {
                return Err(JournalAgentStoreError::CorruptRecord);
            }
            let provisioning = AgentProvisioningV1::new(
                session.request.runtime().clone(),
                session.request.host_channel_binding(),
                *session.response.agent_instance(),
                session.response.features().clone(),
                recovery_authority_binding,
            )
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
            let reducer = GuestAgentReducerV1::restore_checkpoint(provisioning, checkpoint.clone())
                .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
            reducer
                .validate_unreserved_successor(&latest.request)
                .map_err(|_| JournalAgentStoreError::CorruptRecord)
        };
        if latest.outcome.is_none()
            && latest.reservation_sequence >= checkpoint.sequence()
            && operations[..operations.len() - 1]
                .iter()
                .all(|operation| operation.reservation_sequence < checkpoint.sequence())
            && validate_agent_checkpoint_history_v1(checkpoint, &prior_rows, authenticated_binding)
                .is_ok()
            && reservation_is_authenticated_successor().is_ok()
        {
            return Ok(AgentCheckpointProjectionV1::ReservationAhead {
                session: latest.session,
                sequence: latest.sequence,
                request_commitment: latest.request_commitment,
                store_commitment: latest.store_commitment,
            });
        }
    }
    Err(JournalAgentStoreError::CorruptRecord)
}

struct StoredAgentHeadV1 {
    sequence: AgentOperationSequenceV1,
    operation: AgentOperationIdV1,
    request_commitment: ObjectDigest,
}

fn decode_head(bytes: &[u8]) -> Result<StoredAgentHeadV1, JournalAgentStoreError> {
    if bytes.len() != 56 {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    let sequence = AgentOperationSequenceV1::new(u64::from_be_bytes(
        bytes[0..8]
            .try_into()
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?,
    ))
    .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
    let operation = AgentOperationIdV1::new(
        bytes[8..24]
            .try_into()
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?,
    )
    .map_err(|_| JournalAgentStoreError::CorruptRecord)?;
    let request_commitment = ObjectDigest::from_bytes(
        bytes[24..56]
            .try_into()
            .map_err(|_| JournalAgentStoreError::CorruptRecord)?,
    );
    if request_commitment.as_bytes() == &[0; 32] {
        return Err(JournalAgentStoreError::CorruptRecord);
    }
    Ok(StoredAgentHeadV1 {
        sequence,
        operation,
        request_commitment,
    })
}

fn owner_value(store_binding: ObjectDigest, recovery_authority_binding: ObjectDigest) -> Vec<u8> {
    let mut value = Vec::with_capacity(64);
    value.extend_from_slice(store_binding.as_bytes());
    value.extend_from_slice(recovery_authority_binding.as_bytes());
    value
}

fn reservation_commitment(
    binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation: AgentOperationIdV1,
    request: ObjectDigest,
    journal_sequence: u64,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-reservation-store-v1\0");
    digest.update(binding.as_bytes());
    digest.update(recovery_authority_binding.as_bytes());
    digest.update(session.digest().as_bytes());
    digest.update(sequence.get().to_be_bytes());
    digest.update(operation.as_bytes());
    digest.update(request.as_bytes());
    digest.update(journal_sequence.to_be_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn head_state_commitment(head: Option<&[u8]>) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-reservation-predecessor-v1\0");
    match head {
        None => digest.update([0]),
        Some(bytes) => {
            digest.update([1]);
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
    }
    ObjectDigest::from_bytes(digest.finalize().into())
}

#[allow(clippy::too_many_arguments)]
fn reservation_recovery_binding(
    binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    session: AgentSessionBindingV1,
    sequence: AgentOperationSequenceV1,
    operation: AgentOperationIdV1,
    request: ObjectDigest,
    store_commitment: ObjectDigest,
    predecessor_commitment: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-reservation-recovery-v1\0");
    digest.update(binding.as_bytes());
    digest.update(recovery_authority_binding.as_bytes());
    digest.update(session.digest().as_bytes());
    digest.update(sequence.get().to_be_bytes());
    digest.update(operation.as_bytes());
    digest.update(request.as_bytes());
    digest.update(store_commitment.as_bytes());
    digest.update(predecessor_commitment.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn operation_state_commitment(bytes: &[u8]) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-operation-state-v1\0");
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn outcome_recovery_binding(
    binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    reservation: &AgentOperationReservationV1,
    outcome_commitment: ObjectDigest,
    predecessor_commitment: ObjectDigest,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-outcome-recovery-v1\0");
    digest.update(binding.as_bytes());
    digest.update(recovery_authority_binding.as_bytes());
    digest.update(reservation.session().digest().as_bytes());
    digest.update(reservation.sequence().get().to_be_bytes());
    digest.update(reservation.operation_id().as_bytes());
    digest.update(reservation.request_commitment().as_bytes());
    digest.update(reservation.store_commitment().as_bytes());
    digest.update(outcome_commitment.as_bytes());
    digest.update(predecessor_commitment.as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn checkpoint_provenance(
    binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
    checkpoint: &AgentDurableCheckpointV1,
) -> ObjectDigest {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-checkpoint-store-v1\0");
    digest.update(binding.as_bytes());
    digest.update(recovery_authority_binding.as_bytes());
    digest.update(checkpoint.sequence().to_be_bytes());
    digest.update(checkpoint.checkpoint_commitment().as_bytes());
    ObjectDigest::from_bytes(digest.finalize().into())
}

fn authenticated_checkpoint(
    checkpoint: AgentDurableCheckpointV1,
    store_sequence: u64,
    store_binding: ObjectDigest,
    recovery_authority_binding: ObjectDigest,
) -> AuthenticatedJournalAgentCheckpointV1 {
    AuthenticatedJournalAgentCheckpointV1 {
        provenance: checkpoint_provenance(store_binding, recovery_authority_binding, &checkpoint),
        checkpoint,
        store_sequence,
        recovery_authority_binding,
    }
}

fn transaction_id(domain: &[u8], commitment: ObjectDigest) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"aos-sandbox-agent-store-transaction-v1\0");
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update(commitment.as_bytes());
    let result: [u8; 32] = digest.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&result[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    id
}

fn map_cas_journal_error(error: JournalError) -> AgentOperationCasError {
    match error {
        JournalError::IdempotencyConflict => AgentOperationCasError::Equivocation,
        JournalError::SequenceExhausted => AgentOperationCasError::SequenceConflict,
        _ => AgentOperationCasError::InvalidReceipt,
    }
}

/// Reports dedicated dormant agent-store initialization and ownership errors.
#[derive(Debug, thiserror::Error)]
pub enum JournalAgentStoreError {
    /// Store binding is zero.
    #[error("agent journal store binding is invalid")]
    InvalidBinding,
    /// Journal is nonempty, belongs to another owner, or has foreign keys.
    #[error("agent journal is not dedicated to this store")]
    ForeignStore,
    /// Journal sequence cannot advance safely.
    #[error("agent journal sequence is exhausted")]
    SequenceExhausted,
    /// A retained key, value, checkpoint, head, or operation graph is invalid.
    #[error("agent journal retained state is corrupt")]
    CorruptRecord,
    /// Protected journal access or durability failed.
    #[error("agent protected journal failed: {0}")]
    Journal(#[from] JournalError),
}
