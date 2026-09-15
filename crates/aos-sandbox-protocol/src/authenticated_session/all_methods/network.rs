//! Network-specific authenticated success-body validation.

use aos_proto::aos::sandbox::local::v1::{
    BrokerError, BrokerErrorCode, InventoryNetworksResponse, NetworkResult, NetworkState,
};
use aos_sandbox_core::FeatureRef;
use buffa::{Enumeration as _, Message as _};

use crate::ProtocolValidationError;
use crate::semantics::{CanonicalNetworkSemanticsV1, NetworkOperation};

pub(super) fn validate_network_apply_response(
    body: &[u8],
    request: &CanonicalNetworkSemanticsV1,
) -> Result<(), ProtocolValidationError> {
    let result = NetworkResult::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    validate_network_result_shape(&result)?;
    if result.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let state = result
        .state
        .as_known()
        .ok_or(ProtocolValidationError::UnknownState)?;
    let valid = match request.operation() {
        NetworkOperation::Prepare { .. } => {
            state == NetworkState::NETWORK_STATE_DEFAULT_DROP && result.lease_generation == 0
        }
        NetworkOperation::ArmLease {
            network_handle,
            lease_generation,
            ..
        }
        | NetworkOperation::RenewLease {
            network_handle,
            lease_generation,
            ..
        } => {
            result.network_handle.as_slice() == network_handle
                && state == NetworkState::NETWORK_STATE_ARMED
                && result.lease_generation == *lease_generation
        }
        NetworkOperation::Disarm { network_handle } => {
            result.network_handle.as_slice() == network_handle
                && state == NetworkState::NETWORK_STATE_DEFAULT_DROP
                && result.lease_generation == 0
        }
        NetworkOperation::Destroy { network_handle } => {
            result.network_handle.as_slice() == network_handle
                && state == NetworkState::NETWORK_STATE_ABSENT
                && result.lease_generation == 0
        }
    };
    if !valid {
        return Err(ProtocolValidationError::InvalidField(
            "network apply response binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_network_inventory(body: &[u8]) -> Result<(), ProtocolValidationError> {
    let inventory = InventoryNetworksResponse::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !inventory.__buffa_unknown_fields.is_empty() || inventory.networks.len() > 16_384 {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let mut prior_handle: Option<&[u8]> = None;
    for result in &inventory.networks {
        validate_network_result_shape(result)?;
        if prior_handle.is_some_and(|prior| prior >= result.network_handle.as_slice()) {
            return Err(ProtocolValidationError::InvalidField(
                "network inventory order",
            ));
        }
        prior_handle = Some(&result.network_handle);
    }
    if inventory.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    Ok(())
}

fn validate_network_result_shape(result: &NetworkResult) -> Result<(), ProtocolValidationError> {
    let state = result
        .state
        .as_known()
        .filter(|state| *state != NetworkState::NETWORK_STATE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidField("network result"))?;
    let error = result.error.as_option();
    if !result.__buffa_unknown_fields.is_empty()
        || (state == NetworkState::NETWORK_STATE_FAILED) != error.is_some()
    {
        return Err(ProtocolValidationError::InvalidField("network result"));
    }
    if let Some(error) = error {
        validate_embedded_error(error)?;
    }
    crate::exact_nonzero::<32>(&result.network_handle, "network_handle")?;
    Ok(())
}

fn validate_embedded_error(error: &BrokerError) -> Result<(), ProtocolValidationError> {
    if !error.__buffa_unknown_fields.is_empty()
        || error.safe_message.is_empty()
        || error.safe_message.len() > 4096
        || error.safe_message.chars().any(char::is_control)
    {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    let code = error
        .code
        .as_known()
        .filter(|code| *code != BrokerErrorCode::BROKER_ERROR_CODE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidBrokerError)?;
    let missing_feature = error.missing_feature.as_option();
    if (code == BrokerErrorCode::BROKER_ERROR_CODE_REQUIRED_FEATURE_UNAVAILABLE)
        != missing_feature.is_some()
    {
        return Err(ProtocolValidationError::InvalidBrokerError);
    }
    if let Some(feature) = missing_feature {
        if !feature.__buffa_unknown_fields.is_empty()
            || FeatureRef::new(feature.namespace.clone(), feature.major, feature.minor).is_err()
        {
            return Err(ProtocolValidationError::InvalidBrokerError);
        }
    }
    Ok(())
}
