//! Retains the Source provider's exact one-shot legacy capacity custody.
//!
//! Namespace-46 codecs, provenance and settlement comparisons stay in the
//! canonical Protocol and Broker engines. This owner admits only the existing
//! SourceProviderNativeTerminal purpose; other roles keep their actual lenders.

use aos_sandbox_broker::domain_transaction_custody::capacity_records as shared_capacity;

use super::semantic_append::AppendScope;
use super::{
    CommitResult, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace,
};

pub use aos_sandbox_protocol::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRecoveryBindingV1,
    GlobalCapacityReservationRequestV1,
};
pub(super) use aos_sandbox_protocol::domain_ledger::capacity::{
    decode_reservation, reservation_key,
};

fn capacity_record_data(
    reservation: &GlobalCapacityReservationV1,
) -> shared_capacity::RetainedCapacityRecordDataV1 {
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
    pub(super) fn prepare_global_capacity_reservation_v1(
        &self,
        request: GlobalCapacityReservationRequestV1,
        admission_transaction_id: [u8; 16],
    ) -> Result<PreparedGlobalCapacityReservationV1, JournalError> {
        self.ensure_healthy()?;
        require_source_request(&request)?;
        aos_sandbox_protocol::domain_ledger::capacity_family::validate_request_with_limits(
            &request,
            self.native_view().limits(),
        )?;
        let data = shared_capacity::prepare_capacity_record_v1(
            self.historical_read_view_v1(),
            request,
            admission_transaction_id,
        )?;
        Ok(PreparedGlobalCapacityReservationV1 {
            request: data.request,
            admission_transaction_id: data.admission_transaction_id,
            reservation_id: data.reservation_id,
            record: data.record,
        })
    }

    pub(super) fn commit_global_capacity_reservation_v1(
        &mut self,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        require_source_request(&prepared.request)?;
        if *transaction.id() != prepared.admission_transaction_id
            || transaction
                .records()
                .iter()
                .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
                .ne([&prepared.record])
        {
            return Err(JournalError::InvalidTransaction);
        }
        let result = self.commit_in_scope(
            transaction,
            AppendScope {
                allow_capacity_records: true,
                ..AppendScope::default()
            },
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

    pub(super) fn recover_global_capacity_reservation_v1(
        &self,
        reservation_id: [u8; 32],
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.lookup_global_capacity_reservation_v1(reservation_id)?
            .ok_or(JournalError::MalformedRecord(
                "capacity reservation is absent",
            ))
    }

    pub(super) fn lookup_global_capacity_reservation_v1(
        &self,
        expected_reservation_id: [u8; 32],
    ) -> Result<Option<GlobalCapacityReservationV1>, JournalError> {
        self.ensure_healthy()?;
        let Some(data) = shared_capacity::lookup_capacity_record_v1(
            self.historical_read_view_v1(),
            expected_reservation_id,
        )?
        else {
            return Ok(None);
        };
        let data = data.compare_provenance()?;
        require_source_request(&data.request)?;
        Ok(Some(GlobalCapacityReservationV1 {
            request: data.request,
            admission_transaction_id: data.admission_transaction_id,
            reservation_id: data.reservation_id,
            record_digest: data.record_digest,
        }))
    }

    pub(super) fn recover_unique_global_capacity_reservation_v1(
        &self,
        binding: &GlobalCapacityReservationRecoveryBindingV1,
    ) -> Result<GlobalCapacityReservationV1, JournalError> {
        self.ensure_healthy()?;
        if binding.purpose != GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal {
            return Err(JournalError::ForeignAuthorityNamespace);
        }
        let data =
            shared_capacity::unique_capacity_record_v1(self.historical_read_view_v1(), binding)?;
        require_source_request(&data.request)?;
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
        )
    }
}

pub(super) fn validate_settlement_shape(
    journal: &Journal,
    reservation: &GlobalCapacityReservationV1,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    require_source_request(&reservation.request)?;
    if reservation.request.future_transactions != 1 {
        return Err(JournalError::AuthorityPreflightMismatch);
    }
    let _comparison = shared_capacity::compare_capacity_settlement_v1(
        journal.historical_read_view_v1(),
        capacity_record_data(reservation),
        transaction,
    )?;
    Ok(())
}

fn require_source_request(
    request: &GlobalCapacityReservationRequestV1,
) -> Result<(), JournalError> {
    if request.purpose != GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
        || request.owner_namespace != RecordNamespace::SourceProviderAuthority
    {
        return Err(JournalError::ForeignAuthorityNamespace);
    }
    Ok(())
}

fn digest_bytes(value: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(value).into()
}
