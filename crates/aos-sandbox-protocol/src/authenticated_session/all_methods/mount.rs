//! Mount-specific authenticated success-body correlation.

use aos_proto::aos::sandbox::local::v1::{DestinationSlotAction, DestinationSlotLifecycle};
use sha2::{Digest as _, Sha256};

use crate::{
    ProtocolValidationError, ValidatedDestinationSlotOperation, ValidatedDestinationSlotRequest,
    decode_destination_slot_response,
};

pub(super) fn validate_destination_slot_apply_response(
    body: &[u8],
    maximum_response_bytes: u32,
    request: &ValidatedDestinationSlotRequest,
    request_body: &[u8],
) -> Result<(), ProtocolValidationError> {
    let resource = decode_destination_slot_response(body, maximum_response_bytes)?;
    let request_digest: [u8; 32] = Sha256::digest(request_body).into();
    if resource.fence() != request.binding_fence()
        || resource.namespace_generation() != request.namespace_generation()
        || resource.destination_slot_id() != request.destination_slot_id()
        || resource.sandbox_spec() != request.sandbox_spec()
    {
        return Err(ProtocolValidationError::InvalidField(
            "destination-slot response binding",
        ));
    }
    let matches_operation = |operation: ValidatedDestinationSlotOperation| {
        operation.operation_id() == request.header().request_id()
            && operation.request_digest() == &request_digest
    };
    let correlated = match request.action() {
        DestinationSlotAction::DESTINATION_SLOT_ACTION_MATERIALIZE => {
            resource.lifecycle() == DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY
                && matches_operation(resource.materialization())
                && resource.rematerialization().is_none()
                && resource.reap().is_none()
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REMATERIALIZE => {
            resource.rematerialization().is_some_and(|correlation| {
                resource.lifecycle() == DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_READY
                    && matches_operation(correlation.operation())
                    && Some(correlation.expected_resource_digest())
                        == request.expected_resource_digest()
                    && resource.reap().is_none()
            })
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_REAP => {
            resource.reap().is_some_and(|correlation| {
                matches!(
                    resource.lifecycle(),
                    DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_REAPING
                        | DestinationSlotLifecycle::DESTINATION_SLOT_LIFECYCLE_RELEASED
                ) && matches_operation(correlation.operation())
                    && Some(correlation.expected_resource_digest())
                        == request.expected_resource_digest()
            })
        }
        DestinationSlotAction::DESTINATION_SLOT_ACTION_UNSPECIFIED => false,
    };
    if !correlated {
        return Err(ProtocolValidationError::InvalidField(
            "destination-slot response operation correlation",
        ));
    }
    Ok(())
}
