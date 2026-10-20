//! Durable global journal-capacity reservations.
//!
//! Reservations are ordinary replayed records in a closed namespace, but only
//! the methods in this module may append or remove them. Every journal commit
//! accounts for their worst-case retained-record and append-byte budgets.
//! V1 reserves one future transaction. V2 also retains an explicit bounded
//! transaction count for an ordered owner suffix; it cannot infer extra slots
//! from a legacy record or change the closed namespace purpose.
//! Native V3 records use a separate DATA-only codec and bounded profile; replay
//! accounts their floors, but no legacy protected reservation route admits them.
//! Ordinary V4 uses the same canonical family dispatch with a distinct closed
//! DATA codec. The closed kind2 fixed-writer path derives its local commitments;
//! other kinds remain opaque to protected producers. Generic append gates stay
//! closed, and no original native admission follows from canonical floor DATA.

#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::capacity_family::family::accounting_reservation;
use aos_sandbox_protocol::domain_ledger::capacity_family::{
    decode_capacity_reservation_request_v1, legacy_capacity_ids_for_purpose,
    validate_request_with_limits,
};

use crate::journal::CacheMutationGateV1;
use crate::journal::semantic_append::AppendScope;

use aos_sandbox_protocol::domain_ledger::operation::effect_key;
use aos_sandbox_protocol::domain_ledger::controller_history_relation::{
    ControllerCapacityHistoryErrorV1, validate_controller_capacity_transfer_v1,
    validate_controller_capacity_settlement_v1,
};

use sha2::{Digest as _, Sha256};

use super::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};

pub mod native_held;

pub use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1,
};
pub(crate) use aos_sandbox_protocol::domain_ledger::capacity::capacity_reservation_identity_is_exact_v1;
pub(super) use aos_sandbox_protocol::domain_ledger::capacity::{
    decode_reservation, reservation_key,
};
use aos_sandbox_protocol::domain_ledger::capacity::{encode_reservation, reservation_id};
#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::capacity::{uses_v2, valid_future_transactions};
#[cfg(test)]
use aos_sandbox_protocol::domain_ledger::capacity::{RECORD_DOMAIN, VALUE_BYTES_V1, VALUE_BYTES_V2};

use aos_sandbox_broker::domain_transaction_custody::capacity_records as shared_capacity;

fn capacity_record_data(reservation: &GlobalCapacityReservationV1)
    -> shared_capacity::RetainedCapacityRecordDataV1
{
    shared_capacity::RetainedCapacityRecordDataV1 {
        request: reservation.request,
        admission_transaction_id: reservation.admission_transaction_id,
        reservation_id: reservation.reservation_id,
        record_digest: reservation.record_digest,
    }
}

/// Carries the exact reservation record that must join its admission transaction.
#[must_use = "a prepared capacity reservation must be committed or discarded before admission"]
pub struct PreparedGlobalCapacityReservationV1 {
    pub(super) request: GlobalCapacityReservationRequestV1,
    pub(super) admission_transaction_id: [u8; 16],
    pub(super) reservation_id: [u8; 32],
    pub(super) record: JournalRecord,
}

/// Authorizes exactly one terminal settlement against retained global capacity.
#[must_use = "capacity remains reserved until this authority is settled"]
pub struct GlobalCapacityReservationV1 {
    pub(super) request: GlobalCapacityReservationRequestV1,
    pub(super) admission_transaction_id: [u8; 16],
    pub(super) reservation_id: [u8; 32],
    pub(super) record_digest: [u8; 32],
}

impl PreparedGlobalCapacityReservationV1 {
    /// Borrows the exact record callers must include in the admission transaction.
    #[must_use]
    pub const fn record(&self) -> &JournalRecord {
        &self.record
    }

    /// Returns the deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.reservation_id
    }
}

impl GlobalCapacityReservationV1 {
    /// Returns the deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> [u8; 32] {
        self.reservation_id
    }

    /// Returns the owner namespace and stable owner identity.
    #[must_use]
    pub const fn owner(&self) -> (RecordNamespace, [u8; 32]) {
        (self.request.owner_namespace, self.request.owner_id)
    }

    /// Checks every immutable request field and the admission transaction identity.
    #[must_use]
    pub fn matches_request(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> bool {
        self.request == *request && self.admission_transaction_id == admission_transaction_id
    }

    /// Returns the authenticated full request retained in namespace 46.
    #[must_use]
    pub const fn request(&self) -> GlobalCapacityReservationRequestV1 {
        self.request
    }

    /// Returns the exact durable admission transaction identity.
    #[must_use]
    pub const fn admission_transaction_id(&self) -> [u8; 16] {
        self.admission_transaction_id
    }

    /// Returns the exact deletion that must join the terminal transaction.
    #[must_use]
    pub fn settlement_record(&self) -> JournalRecord {
        JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation,
            reservation_key(self.reservation_id),
        )
    }

    pub(super) fn matches_recovery_binding(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> bool {
        capacity_record_data(self).matches_recovery_binding(binding)
    }
}

impl Journal {
    /// Rejoins only one exact fixed-Root genesis reservation after cold replay.
    pub(crate) fn root_source_genesis_capacity_identity_v1(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission: [u8; 16],
    ) -> Result<[u8; 32], JournalError> {
        crate::policy_compiler::require_root_source_genesis_capacity_owner_v1(self)?;
        if request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let identity = reservation_id(request, admission);
        let retained = self.recover_global_capacity_reservation_v1(identity)?;
        if !retained.matches_request(request, admission) {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        Ok(identity)
    }

    pub(crate) fn root_source_genesis_capacity_ids_v1(
        &self,
    ) -> Result<Vec<[u8; 32]>, JournalError> {
        self.ensure_healthy()?;
        legacy_capacity_ids_for_purpose(
            self.native.state(),
            GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor,
        )
        .map_err(JournalError::from)
    }

    /// Lists only canonical Controller-history capacity identities for replay.
    pub(crate) fn controller_project_capacity_ids_v1(&self) -> Result<Vec<[u8; 32]>, JournalError> {
        self.ensure_healthy()?;
        legacy_capacity_ids_for_purpose(
            self.native.state(),
            GlobalCapacityReservationPurposeV1::ControllerProjectAdmission,
        )
        .map_err(JournalError::from)
    }

    /// Transfers Root's two-slot intent to its exact one-slot history suffix.
    ///
    /// The protected intent validator checks the actual terminal row and the
    /// immutable intent; changing a digest on a generic reservation cannot
    /// create Root retirement authority.
    pub(crate) fn transfer_root_project_capacity_v1(
        &mut self,
        reservation: GlobalCapacityReservationV1,
        successor: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.require_project_capacity_suffix(&reservation, &successor, transaction)?;
        let old = reservation.request;
        let new = successor.request;
        if old.purpose != GlobalCapacityReservationPurposeV1::RootProjectAdmission
            || old.future_transactions != 2
            || new.future_transactions != 1
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        crate::policy_compiler::validate_root_project_capacity_transfer_v1(
            self,
            transaction,
            &old,
            &new,
            reservation.reservation_id,
            successor.reservation_id,
        )?;
        self.commit_in_scope(
            transaction,
            AppendScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        self.recover_global_capacity_reservation_v1(successor.reservation_id)
    }

    /// Transfers only the exact Controller project-admission suffix in one cut.
    ///
    /// This purpose-specific path retires the old reservation and records its
    /// smaller successor with the same Effect transition. Generic capacity
    /// settlement still permits only its single exact deletion.
    pub(crate) fn transfer_controller_project_capacity_v1(
        &mut self,
        reservation: GlobalCapacityReservationV1,
        successor: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.require_project_capacity_suffix(&reservation, &successor, transaction)?;
        let old = reservation.request;
        let new = successor.request;
        if old.purpose != GlobalCapacityReservationPurposeV1::ControllerProjectAdmission
            || new.owner_digest != old.owner_digest
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        if transaction.records().len() != 3 {
            return Err(JournalError::InvalidTransaction);
        }
        validate_capacity_transfer(
            self,
            transaction,
            old.operation_id,
            reservation.reservation_id,
            successor.reservation_id,
        )?;
        self.commit_in_scope(
            transaction,
            AppendScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )?;
        self.recover_global_capacity_reservation_v1(successor.reservation_id)
    }

    // Shares only canonical suffix accounting. Owner-specific phase and exact
    // Effect/intent/terminal validators remain mandatory in both callers.
    fn require_project_capacity_suffix(
        &self,
        reservation: &GlobalCapacityReservationV1,
        successor: &PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        let current = self.recover_global_capacity_reservation_v1(reservation.reservation_id)?;
        let old = reservation.request;
        let new = successor.request;
        if current.request != old
            || current.record_digest != reservation.record_digest
            || current.admission_transaction_id != reservation.admission_transaction_id
            || new.purpose != old.purpose
            || new.owner_namespace != old.owner_namespace
            || new.owner_id != old.owner_id
            || new.operation_id != old.operation_id
            || new.artifact_digest != old.artifact_digest
            || new.checkpoint_digest != old.checkpoint_digest
            || new.chain_head_digest != old.chain_head_digest
            || old.future_transactions <= 1
            || new.future_transactions != old.future_transactions - 1
            || old.terminal_records != old.poison_records
            || old.terminal_bytes != old.poison_bytes
            || new.terminal_records != new.poison_records
            || new.terminal_bytes != new.poison_bytes
            || successor.admission_transaction_id != *transaction.id()
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        let capacity_records = transaction
            .records()
            .iter()
            .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
            .collect::<Vec<_>>();
        let deletion = reservation.settlement_record();
        let records = u32::try_from(transaction.records().len())
            .map_err(|_| JournalError::InvalidTransaction)?;
        if capacity_records != [&deletion, &successor.record]
            || old.terminal_records.checked_sub(records) != Some(new.terminal_records)
            || old
                .terminal_bytes
                .checked_sub(super::encoded_transaction_append_bytes(transaction)?)
                != Some(new.terminal_bytes)
        {
            return Err(JournalError::AuthorityPreflightMismatch);
        }
        Ok(())
    }

    /// Prepares a durable reservation record for an exact admission transaction.
    ///
    /// # Errors
    ///
    /// Returns an error for sentinel bindings, zero or oversized budgets,
    /// duplicate reservation identity, or an invalid admission transaction ID.
    pub(crate) fn prepare_global_capacity_reservation_v1(
        &self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<PreparedGlobalCapacityReservationV1, JournalError> {
        self.ensure_healthy()?;
        if request.purpose.is_first_source_successor() {
            return Err(JournalError::ProtectedBoundary);
        }
        validate_request(&request, self)?;
        if request.purpose == GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            crate::policy_compiler::require_root_source_genesis_capacity_owner_v1(self)?;
        }
        let data = shared_capacity::prepare_capacity_record_v1(
            self.historical_read_view_v1(), request, admission_transaction_id,
        ).map_err(JournalError::from)?;
        Ok(PreparedGlobalCapacityReservationV1 {
            request: data.request,
            admission_transaction_id: data.admission_transaction_id,
            reservation_id: data.reservation_id,
            record: data.record,
        })
    }

    /// Commits admission and its capacity reservation atomically.
    ///
    /// # Errors
    ///
    /// Returns an error unless the transaction ID and exact reservation record
    /// match the prepared authority and all journal and reserved-capacity bounds hold.
    pub(crate) fn commit_global_capacity_reservation_v1(
        &mut self,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        if prepared.request.purpose.is_first_source_successor() {
            return Err(JournalError::ProtectedBoundary);
        }
        if prepared.request.purpose == GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            crate::policy_compiler::validate_root_source_genesis_capacity_admission_v1(
                self,
                transaction,
                &prepared.request,
            )?;
        }
        if *transaction.id() != prepared.admission_transaction_id
            || transaction
                .records()
                .iter()
                .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
                .ne([&prepared.record])
        {
            return Err(JournalError::InvalidTransaction);
        }
        let result =
            self.commit_in_scope(
                transaction,
                AppendScope {
                    allow_capacity_records: true,
                    ..AppendScope::default()
                },
                CacheMutationGateV1::Ordinary,
            )?;
        let record_digest = digest_bytes(
            prepared
                .record
                .value()
                .ok_or(JournalError::InvalidTransaction)?,
        );
        Ok((
            result,
            GlobalCapacityReservationV1 {
                request: prepared.request,
                admission_transaction_id: prepared.admission_transaction_id,
                reservation_id: prepared.reservation_id,
                record_digest,
            },
        ))
    }

    /// Recovers the one-shot settlement authority from an exact replayed reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is absent, malformed, or names a
    /// different admission transaction or record digest.
    pub(crate) fn recover_global_capacity_reservation_v1(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.lookup_global_capacity_reservation_v1(reservation_id)?
            .ok_or(JournalError::MalformedRecord(
                "capacity reservation is absent",
            ))
    }

    /// Looks up one reservation without conflating authenticated absence with
    /// malformed state or failed provenance validation.
    pub(crate) fn lookup_global_capacity_reservation_v1(
        &self,
        expected_reservation_id: [u8; 32],
    ) -> Result<Option<GlobalCapacityReservationV1>, JournalError> {
        self.ensure_healthy()?;
        let Some(data) = shared_capacity::lookup_capacity_record_v1(
            self.historical_read_view_v1(), expected_reservation_id,
        ).map_err(JournalError::from)? else {
            return Ok(None);
        };
        if data.request.purpose.is_first_source_successor() {
            return Err(JournalError::ProtectedBoundary);
        }
        let data = data.compare_provenance().map_err(JournalError::from)?;
        Ok(Some(GlobalCapacityReservationV1 {
            request: data.request,
            admission_transaction_id: data.admission_transaction_id,
            reservation_id: data.reservation_id,
            record_digest: data.record_digest,
        }))
    }

    /// Recovers the unique reservation matching one complete stable binding.
    pub(crate) fn recover_unique_global_capacity_reservation_v1(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.ensure_healthy()?;
        if binding.purpose.is_first_source_successor() {
            return Err(JournalError::ProtectedBoundary);
        }
        let data = shared_capacity::unique_capacity_record_v1(self.historical_read_view_v1(), binding)
            .map_err(JournalError::from)?;
        Ok(GlobalCapacityReservationV1 {
            request: data.request,
            admission_transaction_id: data.admission_transaction_id,
            reservation_id: data.reservation_id,
            record_digest: data.record_digest,
        })
    }

    pub(super) fn settle_global_capacity_reservation_v1(
        &mut self,
        reservation: GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        validate_settlement_shape(self, &reservation, transaction)?;
        self.commit_in_scope(
            transaction,
            AppendScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }
}

pub(super) fn validate_settlement_shape(
    journal: &Journal,
    reservation: &GlobalCapacityReservationV1,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if reservation.request.purpose.is_first_source_successor() {
        return Err(JournalError::ProtectedBoundary);
    }
    if reservation.request.future_transactions != 1 {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    let _comparison = shared_capacity::compare_capacity_settlement_v1(
        journal.historical_read_view_v1(), capacity_record_data(reservation), transaction,
    ).map_err(JournalError::from)?;
    if reservation.request.purpose == GlobalCapacityReservationPurposeV1::ControllerProjectAdmission
    {
        validate_capacity_settlement(
            journal,
            transaction,
            reservation.request.operation_id,
            reservation.reservation_id,
        )?;
    }
    if reservation.request.purpose == GlobalCapacityReservationPurposeV1::RootProjectAdmission {
        crate::policy_compiler::validate_root_project_capacity_settlement_v1(
            journal,
            transaction,
            &reservation.request,
            reservation.reservation_id,
        )?;
    }
    if reservation.request.purpose == GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
        crate::policy_compiler::validate_root_source_genesis_capacity_settlement_v1(
            journal,
            transaction,
            &reservation.request,
            reservation.reservation_id,
        )?;
    }
    Ok(())
}

fn validate_request(
    request: &GlobalCapacityReservationRequestV1,
    journal: &Journal,
) -> Result<(), JournalError> {
    validate_request_with_limits(request, journal.native.limits()).map_err(JournalError::from)
}

/// Constructs fixed reservation DATA without conferring named-owner custody.
///
/// # Errors
/// Rejects a generic purpose, foreign namespace or sentinel admission identity.
pub(crate) fn first_source_successor_capacity_record_v2(
    request: &GlobalCapacityReservationRequestV1,
    admission: [u8; 16],
) -> Result<JournalRecord, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::first_source_successor_capacity_record_v2(request, admission)
        .map_err(JournalError::from)
}

/// Rejoins the exact native reservation before constructing its deletion DATA.
///
/// # Errors
/// Rejects malformed capacity families or changed request/admission bytes.
pub(crate) fn first_source_successor_capacity_delete_v2(
    state: &std::collections::BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    request: &GlobalCapacityReservationRequestV1,
    admission: [u8; 16],
) -> Result<JournalRecord, JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::first_source_successor_capacity_delete_v2(state, request, admission)
        .map_err(JournalError::from)
}

/// Derives the canonical identity of one closed native reservation.
///
/// # Errors
/// Rejects a generic purpose, foreign namespace or sentinel admission identity.
pub(crate) fn first_source_successor_capacity_identity_v2(
    request: &GlobalCapacityReservationRequestV1,
    admission: [u8; 16],
) -> Result<[u8; 32], JournalError> {
    aos_sandbox_ledger_replay::replay::source_tree_successor::first_source_successor_capacity_identity_v2(request, admission)
        .map_err(JournalError::from)
}

pub(super) fn validate_first_source_successor_capacity_records_v2(
    journal: &Journal,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    for record in transaction.records() {
        if record.namespace() != RecordNamespace::GlobalCapacityReservation
            || record.value().is_none()
        {
            continue;
        }
        let (request, admission, _) = decode_capacity_reservation_request_v1(record)?;
        if !request.purpose.is_first_source_successor() || &admission != transaction.id() {
            return Err(JournalError::ProtectedBoundary);
        }
        validate_request(&request, journal)?;
    }
    Ok(())
}

impl Journal {
    /// Prepares closed native reservation DATA under its actual named owner.
    ///
    /// # Errors
    /// Rejects changed custody, invalid limits or a retained duplicate identity.
    pub(crate) fn prepare_first_source_successor_capacity_v2(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission: [u8; 16],
    ) -> Result<JournalRecord, JournalError> {
        super::source_tree_successor::require_capacity_owner(self, request.purpose)?;
        validate_request(request, self)?;
        let record = first_source_successor_capacity_record_v2(request, admission)?;
        if self.native.state().contains_key(&(record.namespace(), record.key().to_vec())) {
            return Err(JournalError::DuplicateRecordKey);
        }
        Ok(record)
    }

    /// Rejoins a closed native deletion under its actual named owner.
    ///
    /// # Errors
    /// Rejects changed custody, malformed families or altered reservation bytes.
    pub(crate) fn first_source_successor_capacity_deletion_v2(
        &self,
        request: &GlobalCapacityReservationRequestV1,
        admission: [u8; 16],
    ) -> Result<JournalRecord, JournalError> {
        super::source_tree_successor::require_capacity_owner(self, request.purpose)?;
        first_source_successor_capacity_delete_v2(self.native.state(), request, admission)
    }
}

pub(in crate::journal) fn digest_bytes(value: &[u8]) -> [u8; 32] {
    aos_sandbox_ledger_replay::replay::digest_bytes(value)
}

fn validate_capacity_transfer(
    journal: &Journal,
    transaction: &JournalTransaction,
    operation: [u8; 16],
    old_capacity: [u8; 32],
    new_capacity: [u8; 32],
) -> Result<(), JournalError> {
    let (key, prior) = borrow_controller_capacity_predecessor(journal, operation)?;
    validate_controller_capacity_transfer_v1(prior, &key, transaction, old_capacity, new_capacity)
        .map_err(controller_capacity_relation_error)
}

fn validate_capacity_settlement(
    journal: &Journal,
    transaction: &JournalTransaction,
    operation: [u8; 16],
    capacity: [u8; 32],
) -> Result<(), JournalError> {
    let (key, prior) = borrow_controller_capacity_predecessor(journal, operation)?;
    validate_controller_capacity_settlement_v1(prior, &key, transaction, capacity)
        .map_err(controller_capacity_relation_error)
}

// Select once through the real Journal before the complete historical relation.
fn borrow_controller_capacity_predecessor(
    journal: &Journal,
    operation: [u8; 16],
) -> Result<([u8; 20], &[u8]), JournalError> {
    let operation = aos_sandbox_model::OperationId::from_bytes(operation);
    let key = effect_key(operation, 0);
    let prior = journal
        .get(RecordNamespace::Effect, &key)
        .ok_or(JournalError::ProtectedBoundary)?;
    Ok((key, prior))
}

fn controller_capacity_relation_error(error: ControllerCapacityHistoryErrorV1) -> JournalError {
    match error {
        ControllerCapacityHistoryErrorV1::ProtectedBoundary => JournalError::ProtectedBoundary,
        ControllerCapacityHistoryErrorV1::AuthorityPreflightMismatch => {
            JournalError::AuthorityPreflightMismatch
        }
    }
}

#[cfg(test)]
mod purpose_tests {
    use super::*;

    fn root_request() -> GlobalCapacityReservationRequestV1 {
        GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::RootProjectAdmission,
            owner_namespace: RecordNamespace::DesiredState,
            owner_id: [1; 32],
            owner_digest: [2; 32],
            operation_id: [3; 16],
            artifact_digest: [4; 32],
            checkpoint_digest: [5; 32],
            chain_head_digest: [6; 32],
            future_transactions: 1,
            terminal_records: 2,
            terminal_bytes: 1024,
            poison_records: 2,
            poison_bytes: 1024,
        }
    }

    #[test]
    fn root_project_capacity_uses_exact_purpose_four() {
        let request = root_request();
        let admission = [7; 16];
        let id = reservation_id(&request, admission);
        let value = encode_reservation(&request, admission, id);

        assert_eq!(value[11], 4);
        assert_eq!(
            decode_reservation(&value).unwrap(),
            (request, admission, id)
        );
        assert!(
            accounting_reservation(&reservation_key(id), &value)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(request.purpose.permits(RecordNamespace::DesiredState));
        assert!(
            !request
                .purpose
                .permits(RecordNamespace::SourceProviderAuthority)
        );
    }

    #[test]
    fn provider_and_root_capacity_keep_distinct_owner_namespaces() {
        let root = root_request();
        let source = GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
            owner_namespace: RecordNamespace::SourceProviderAuthority,
            ..root
        };
        let admission = [7; 16];
        let id = reservation_id(&source, admission);
        let value = encode_reservation(&source, admission, id);

        assert_eq!(value[11], 3);
        assert_ne!(id, reservation_id(&root, admission));
        assert_eq!(decode_reservation(&value).unwrap(), (source, admission, id));
        assert!(
            accounting_reservation(&reservation_key(id), &value)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(
            source
                .purpose
                .permits(RecordNamespace::SourceProviderAuthority)
        );
        assert!(!source.purpose.permits(RecordNamespace::DesiredState));
        assert!(
            !root
                .purpose
                .permits(RecordNamespace::SourceProviderAuthority)
        );

        // Matching digests do not let either purpose borrow the other owner.
        for foreign in [
            GlobalCapacityReservationRequestV1 {
                owner_namespace: root.owner_namespace,
                ..source
            },
            GlobalCapacityReservationRequestV1 {
                owner_namespace: source.owner_namespace,
                ..root
            },
        ] {
            let id = reservation_id(&foreign, admission);
            let value = encode_reservation(&foreign, admission, id);
            assert!(
                accounting_reservation(&reservation_key(id), &value)
                    .map_err(JournalError::from)
                    .is_err()
            );
        }
    }

    #[test]
    fn historical_root_purpose_three_cannot_become_provider_capacity() {
        let request = root_request();
        let admission = [7; 16];
        let mut value = encode_reservation(&request, admission, [0; 32]);
        value[11] = 3;

        // Recompute the complete old record identity, rather than relying on
        // a stale checksum to reject it. Even a reader that recognizes the
        // independent Provider purpose must reject this DesiredState owner.
        let mut digest = Sha256::new();
        digest.update(RECORD_DOMAIN);
        digest.update([value[11], value[10]]);
        digest.update(&value[14..VALUE_BYTES_V1 - 32]);
        let id: [u8; 32] = digest.finalize().into();
        value[VALUE_BYTES_V1 - 32..].copy_from_slice(&id);

        assert!(
            accounting_reservation(&reservation_key(id), &value)
                .map_err(JournalError::from)
                .is_err()
        );
    }

    #[test]
    fn root_project_recovery_rejects_well_formed_foreign_purpose() {
        let request = root_request();
        let binding = GlobalCapacityReservationRecoveryBindingV1 {
            purpose: request.purpose,
            operation_id: request.operation_id,
            artifact_digest: request.artifact_digest,
            checkpoint_digest: request.checkpoint_digest,
            chain_head_digest: request.chain_head_digest,
            future_transactions: request.future_transactions,
            terminal_records: request.terminal_records,
            terminal_bytes: request.terminal_bytes,
            poison_records: request.poison_records,
            poison_bytes: request.poison_bytes,
        };
        let mut foreign = request;
        foreign.purpose = GlobalCapacityReservationPurposeV1::RuntimeExecution;
        foreign.owner_namespace = RecordNamespace::Effect;
        let admission = [7; 16];
        let id = reservation_id(&foreign, admission);
        let value = encode_reservation(&foreign, admission, id);
        let reservation = GlobalCapacityReservationV1 {
            request: foreign,
            admission_transaction_id: admission,
            reservation_id: id,
            record_digest: digest_bytes(&value),
        };

        assert!(
            accounting_reservation(&reservation_key(id), &value)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(!reservation.matches_recovery_binding(&binding));
    }

    #[test]
    fn project_suffix_counts_are_explicit_canonical_and_purpose_limited() {
        for (purpose, counts) in [
            (
                GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
                vec![1],
            ),
            (
                GlobalCapacityReservationPurposeV1::RootProjectAdmission,
                vec![1, 2],
            ),
            (
                GlobalCapacityReservationPurposeV1::ControllerProjectAdmission,
                vec![1, 2, 3],
            ),
        ] {
            for count in counts {
                let mut request = root_request();
                request.purpose = purpose;
                request.owner_namespace = purpose.owner_namespace();
                request.future_transactions = count;
                let admission = [7; 16];
                let identifier = reservation_id(&request, admission);
                let bytes = encode_reservation(&request, admission, identifier);

                assert_eq!(
                    decode_reservation(&bytes).unwrap(),
                    (request, admission, identifier)
                );
                assert!(
                    accounting_reservation(&reservation_key(identifier), &bytes)
                        .map_err(JournalError::from)
                        .is_ok()
                );
                assert_eq!(
                    bytes.len(),
                    if uses_v2(&request) {
                        VALUE_BYTES_V2
                    } else {
                        VALUE_BYTES_V1
                    }
                );
            }
        }

        for purpose in [
            GlobalCapacityReservationPurposeV1::PublisherCompletion,
            GlobalCapacityReservationPurposeV1::RuntimeExecution,
            GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
            GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor,
            GlobalCapacityReservationPurposeV1::ControllerConsumerResource,
        ] {
            for count in [0, 2, 3, 4] {
                let mut request = root_request();
                request.purpose = purpose;
                request.owner_namespace = purpose.owner_namespace();
                request.future_transactions = count;
                let identifier = reservation_id(&request, [7; 16]);
                let bytes = encode_reservation(&request, [7; 16], identifier);

                assert!(
                    decode_reservation(&bytes).is_err(),
                    "foreign purpose {purpose:?}, count {count}"
                );
            }
        }
        assert!(!valid_future_transactions(
            GlobalCapacityReservationPurposeV1::RootProjectAdmission,
            3
        ));
        assert!(!valid_future_transactions(
            GlobalCapacityReservationPurposeV1::ControllerProjectAdmission,
            4
        ));
    }

    #[test]
    fn root_genesis_capacity_is_a_distinct_single_slot_purpose() {
        let mut request = root_request();
        request.purpose = GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor;
        request.owner_namespace = request.purpose.owner_namespace();
        let admission = [7; 16];
        let identifier = reservation_id(&request, admission);
        let bytes = encode_reservation(&request, admission, identifier);

        assert_eq!(bytes.len(), VALUE_BYTES_V1);
        assert_eq!(decode_reservation(&bytes).unwrap().0, request);
        assert!(request.purpose.permits(RecordNamespace::DesiredState));
        assert!(
            !request
                .purpose
                .permits(RecordNamespace::SourceProviderAuthority)
        );
        assert!(!request.purpose.permits(RecordNamespace::Effect));

        for foreign in [
            GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal,
            GlobalCapacityReservationPurposeV1::RootProjectAdmission,
            GlobalCapacityReservationPurposeV1::ControllerProjectAdmission,
        ] {
            let mut changed = request;
            changed.purpose = foreign;
            changed.owner_namespace = foreign.owner_namespace();
            assert_ne!(reservation_id(&changed, admission), identifier);
        }
    }

    #[test]
    fn consumer_resource_capacity_has_only_its_local_namespace_and_one_slot() {
        let mut request = root_request();
        request.purpose = GlobalCapacityReservationPurposeV1::ControllerConsumerResource;
        request.owner_namespace = RecordNamespace::ControllerConsumerReadAttempt;
        let identifier = reservation_id(&request, [7; 16]);
        let bytes = encode_reservation(&request, [7; 16], identifier);

        assert_eq!(bytes.len(), VALUE_BYTES_V1);
        assert_eq!(bytes[11], 7);
        assert_eq!(decode_reservation(&bytes).unwrap().0, request);
        assert!(
            accounting_reservation(&reservation_key(identifier), &bytes)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(
            request
                .purpose
                .permits(RecordNamespace::ControllerConsumerReadAttempt)
        );
        assert!(
            request
                .purpose
                .permits(RecordNamespace::GlobalCapacityReservation)
        );
        for foreign in [
            RecordNamespace::DesiredState,
            RecordNamespace::Effect,
            RecordNamespace::MountAttempt,
            RecordNamespace::SourceProviderAuthority,
        ] {
            assert!(!request.purpose.permits(foreign));
        }
        for code in [0, 11, 255] {
            assert!(GlobalCapacityReservationPurposeV1::from_byte(code).is_err());
        }
    }

    #[test]
    fn legacy_one_slot_is_not_upgraded_by_padding_or_replay_binding() {
        let request = root_request();
        let admission = [7; 16];
        let identifier = reservation_id(&request, admission);
        let bytes = encode_reservation(&request, admission, identifier);
        assert_eq!(bytes.len(), VALUE_BYTES_V1);
        assert_eq!(decode_reservation(&bytes).unwrap().0.future_transactions, 1);

        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0; 4]);
        assert!(decode_reservation(&padded).is_err());
        let mut relabeled = bytes;
        relabeled[8..10].copy_from_slice(&2_u16.to_be_bytes());
        assert!(decode_reservation(&relabeled).is_err());
        let mut wider = request;
        wider.future_transactions = 2;
        assert_ne!(reservation_id(&wider, admission), identifier);
    }
}

#[cfg(test)]
#[path = "capacity_reservation/tests/ordinary.rs"]
mod ordinary_tests;

#[cfg(test)]
#[path = "capacity_reservation/tests/query.rs"]
mod query_tests;
