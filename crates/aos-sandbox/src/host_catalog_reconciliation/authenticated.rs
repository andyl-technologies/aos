//! Confirms durable pending catalogs from exact authenticated Host outcomes.
//!
//! The sole protected request/outcome decoders already retain and join the
//! validated publication coordinates. Confirmation compares that same context
//! with the canonical pending record; it does not parse another Header or
//! reconstruct request state. Native Session disposition remains independent.

use aos_proto::aos::sandbox::local::v1::BrokerMethod;
use aos_sandbox_core::ObjectDigest;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};

use super::{
    CatalogHistory, CatalogRecord, DurableCurrentHostCatalogV1, DurablePendingHostCatalogV1,
    HostCatalogPublicationError, HostCatalogReconciliationError, Journal, commit_confirmation,
};

pub(crate) fn complete_publication(
    journal: &mut Journal,
    pending: DurablePendingHostCatalogV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<DurableCurrentHostCatalogV1, HostCatalogReconciliationError> {
    journal.ensure_protected_authority()?;
    if CatalogHistory::load(journal)?.pending.as_ref() != Some(&pending.record) {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    validate_pending_outcome_binding_v2(&pending.record, outcome)?;
    commit_confirmation(journal, pending)
}

// This is shared semantic comparison, not a native completion port. The
// selected Start caller must first bind real Session IO/native receipts and
// later use its separate paid confirmation append scope.
pub(super) fn validate_pending_outcome_binding_v2(
    pending: &CatalogRecord,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<(), HostCatalogReconciliationError> {
    if outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }
    let request = outcome
        .request()
        .host_catalog_publication_data_v2()
        .ok_or(HostCatalogReconciliationError::InventoryConflict)?;
    validate_coordinates(
        pending.catalog.generation(),
        pending.canonical_catalog.len(),
        ObjectDigest::from_bytes(pending.catalog_digest),
        request.catalog_generation(),
        request.catalog_bytes(),
        request.catalog_digest(),
    )?;
    // Authenticated outcome construction already runs the sole publication
    // receipt decoder and checks its generation/digest against THIS retained
    // request context. An error response cannot confirm a pending catalog.
    match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { .. } => Ok(()),
        AuthenticatedBrokerMethodResultV1::Error(error) => {
            Err(HostCatalogPublicationError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            }
            .into())
        }
    }
}

fn validate_coordinates(
    expected_generation: u64,
    expected_bytes: usize,
    expected_digest: ObjectDigest,
    actual_generation: u64,
    actual_bytes: u64,
    actual_digest: ObjectDigest,
) -> Result<(), HostCatalogPublicationError> {
    if expected_generation != actual_generation
        || u64::try_from(expected_bytes).ok() != Some(actual_bytes)
        || expected_digest != actual_digest
    {
        return Err(HostCatalogPublicationError::ReceiptMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_pending_must_match_all_retained_request_coordinates() {
        let digest = ObjectDigest::from_bytes([7; 32]);
        assert!(validate_coordinates(4, 31, digest, 4, 31, digest).is_ok());

        assert!(validate_coordinates(4, 31, digest, 5, 31, digest).is_err());
        assert!(validate_coordinates(4, 31, digest, 4, 32, digest).is_err());
        assert!(
            validate_coordinates(4, 31, digest, 4, 31, ObjectDigest::from_bytes([8; 32])).is_err()
        );
    }
}
