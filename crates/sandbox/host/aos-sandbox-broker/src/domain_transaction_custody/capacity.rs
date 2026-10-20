//! Shares canonical capacity composition DATA without reservation authority.
//!
//! Fixed purpose/schema admission, original payment, actual reservation custody
//! and native mutation remain inside each real private role adapter. These
//! functions compose and compare bytes only; no result authorizes settlement.

use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::capacity::GlobalCapacityReservationPurposeV1;
use aos_sandbox_protocol::domain_ledger::transaction::{JournalRecord, JournalTransaction};

/// Preserves the existing sole canonical capacity error DATA classifications.
pub use aos_sandbox_protocol::domain_ledger::capacity_family::CapacityDataError
    as DomainCapacityDataErrorV1;

/// Joins exactly one canonical reservation record to its domain transaction.
///
/// # Errors
/// Refuses a foreign reservation record, an existing capacity member, or the
/// unchanged canonical transaction constructor's error.
pub fn capacity_admission_transaction(
    domain: &JournalTransaction,
    reservation: &JournalRecord,
) -> Result<JournalTransaction, DomainCapacityDataErrorV1> {
    if reservation.namespace() != RecordNamespace::GlobalCapacityReservation
        || domain
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
    {
        return Err(DomainCapacityDataErrorV1::InvalidTransaction);
    }
    let mut records = domain.records().to_vec();
    records.push(reservation.clone());
    JournalTransaction::new(*domain.id(), records).map_err(DomainCapacityDataErrorV1::from)
}

/// Compares the original finite purpose and namespace combination.
///
/// # Errors
/// Refuses a foreign namespace or unsupported closed purpose combination.
pub fn validate_capacity_domain_shape(
    transaction: &JournalTransaction,
    purpose: GlobalCapacityReservationPurposeV1,
) -> Result<(), DomainCapacityDataErrorV1> {
    let mut publisher_authority = false;
    let mut publication = false;
    let mut effect = false;
    for record in transaction.records() {
        match record.namespace() {
            RecordNamespace::PublisherAuthority => publisher_authority = true,
            RecordNamespace::AuthorityPublication => publication = true,
            RecordNamespace::Effect => effect = true,
            _ => return Err(DomainCapacityDataErrorV1::ForeignAuthorityNamespace),
        }
    }
    let closed = match purpose {
        GlobalCapacityReservationPurposeV1::PublisherCompletion => {
            publisher_authority && publication
        }
        GlobalCapacityReservationPurposeV1::RuntimeExecution => {
            effect && !publisher_authority && !publication
        }
        GlobalCapacityReservationPurposeV1::RootProjectAdmission
        | GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal
        | GlobalCapacityReservationPurposeV1::ControllerProjectAdmission
        | GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
        | GlobalCapacityReservationPurposeV1::ControllerConsumerResource
        | GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor
        | GlobalCapacityReservationPurposeV1::SourceFirstSourceSuccessorAck
        | GlobalCapacityReservationPurposeV1::ControllerFirstSourceSuccessorComplete => false,
    };
    closed
        .then_some(())
        .ok_or(DomainCapacityDataErrorV1::ForeignAuthorityNamespace)
}

/// Joins the exact deletion DATA through the same composition engine.
///
/// # Errors
/// Preserves the admission composition's namespace and transaction refusals.
pub fn capacity_settlement_transaction(
    domain: &JournalTransaction,
    settlement: JournalRecord,
) -> Result<JournalTransaction, DomainCapacityDataErrorV1> {
    capacity_admission_transaction(domain, &settlement)
}
