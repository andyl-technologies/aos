//! Confirms durable pending catalogs from exact authenticated Host outcomes.
//!
//! Transport recovery and live session currentness remain the protected
//! transport owner's responsibility. A confirmation checks both the request
//! and receipt against the pending bytes before advancing controller state.

use aos_proto::aos::sandbox::local::v1::{BrokerMethod, PublishHostCatalogRequest};
use aos_sandbox_protocol::ProtocolValidationError;
use aos_sandbox_protocol::authenticated_session::all_methods::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodResultV1,
    AuthenticatedBrokerOutcomeDirectionV1,
};
use aos_sandbox_protocol::host_catalog::decode_host_catalog_publication_response;
use buffa::Message as _;

use super::{
    CatalogHistory, DurableCurrentHostCatalogV1, DurablePendingHostCatalogV1,
    HostCatalogPublicationDraftV1, HostCatalogPublicationError, HostCatalogReconciliationError,
    Journal, commit_confirmation,
};

pub(crate) fn complete_publication(
    journal: &mut Journal,
    pending: DurablePendingHostCatalogV1,
    outcome: &AuthenticatedBrokerMethodOutcomeV1,
) -> Result<DurableCurrentHostCatalogV1, HostCatalogReconciliationError> {
    journal.ensure_protected_authority()?;
    if CatalogHistory::load(journal)?.pending.as_ref() != Some(&pending.record)
        || outcome.direction() != AuthenticatedBrokerOutcomeDirectionV1::ClientReceive
        || outcome.method() != BrokerMethod::BROKER_METHOD_HOST_PUBLISH_CATALOG
    {
        return Err(HostCatalogReconciliationError::InventoryConflict);
    }

    let draft = HostCatalogPublicationDraftV1::new(
        pending.canonical_catalog().to_vec(),
        pending.generation(),
    )?;
    validate_request_binding(&draft, outcome.request().exact_body())?;
    let body = match outcome.result() {
        AuthenticatedBrokerMethodResultV1::Success { exact_body, .. } => exact_body,
        AuthenticatedBrokerMethodResultV1::Error(error) => {
            return Err(HostCatalogPublicationError::BrokerRejected {
                code: error.code(),
                retryable: error.retryable(),
            }
            .into());
        }
    };
    validate_receipt_binding(&draft, body)?;

    commit_confirmation(journal, pending)
}

fn validate_request_binding(
    draft: &HostCatalogPublicationDraftV1,
    body: &[u8],
) -> Result<(), HostCatalogPublicationError> {
    // Session admission already validated the header, deadline, descriptors,
    // and signature. Decode only to compare the exact publication coordinates.
    let request = PublishHostCatalogRequest::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if request.catalog_generation != draft.expected_generation()
        || request.catalog_bytes != draft.canonical_catalog().len() as u64
        || request.catalog_sha256.as_slice() != draft.expected_digest().as_bytes()
    {
        return Err(HostCatalogPublicationError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_receipt_binding(
    draft: &HostCatalogPublicationDraftV1,
    body: &[u8],
) -> Result<(), HostCatalogPublicationError> {
    let receipt = decode_host_catalog_publication_response(body)?;
    if receipt.generation() != draft.expected_generation()
        || receipt.catalog_digest() != draft.expected_digest()
    {
        return Err(HostCatalogPublicationError::ReceiptMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_proto::aos::sandbox::local::v1::{
        HostCatalogPublicationStatus, PublishHostCatalogResponse,
    };

    #[test]
    fn request_must_bind_exact_generation_length_and_digest() {
        let draft = HostCatalogPublicationDraftV1::new(vec![1, 2, 3], 7).unwrap();
        let request = PublishHostCatalogRequest {
            catalog_generation: 7,
            catalog_bytes: 3,
            catalog_sha256: draft.expected_digest().as_bytes().to_vec(),
            ..Default::default()
        };
        assert!(validate_request_binding(&draft, &request.encode_to_vec()).is_ok());

        let mut changed = request.clone();
        changed.catalog_generation += 1;
        assert!(validate_request_binding(&draft, &changed.encode_to_vec()).is_err());

        let mut changed = request.clone();
        changed.catalog_bytes += 1;
        assert!(validate_request_binding(&draft, &changed.encode_to_vec()).is_err());

        let mut changed = request;
        changed.catalog_sha256[0] ^= 1;
        assert!(validate_request_binding(&draft, &changed.encode_to_vec()).is_err());
    }

    #[test]
    fn published_and_replayed_receipts_require_exact_catalog() {
        let draft = HostCatalogPublicationDraftV1::new(vec![1, 2, 3], 7).unwrap();
        for status in [
            HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_PUBLISHED,
            HostCatalogPublicationStatus::HOST_CATALOG_PUBLICATION_STATUS_REPLAY,
        ] {
            let receipt = PublishHostCatalogResponse {
                status: status.into(),
                generation: 7,
                catalog_sha256: draft.expected_digest().as_bytes().to_vec(),
                ..Default::default()
            };
            assert!(validate_receipt_binding(&draft, &receipt.encode_to_vec()).is_ok());

            let mut changed = receipt.clone();
            changed.generation += 1;
            assert!(validate_receipt_binding(&draft, &changed.encode_to_vec()).is_err());

            let mut changed = receipt;
            changed.catalog_sha256[0] ^= 1;
            assert!(validate_receipt_binding(&draft, &changed.encode_to_vec()).is_err());
        }
    }
}
