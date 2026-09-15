//! Host-specific authenticated success-body validation.

use aos_proto::aos::sandbox::local::v1::{
    BrokerError, BrokerErrorCode, InventoryRuntimeResponse, RuntimeObservation, RuntimeState,
};
use aos_sandbox_core::FeatureRef;
use buffa::{Enumeration as _, Message as _};

use crate::{ProtocolValidationError, ValidatedObserveRuntimeRequestV1};

pub(super) fn validate_runtime_observation(
    body: &[u8],
    expected: &ValidatedObserveRuntimeRequestV1,
) -> Result<(), ProtocolValidationError> {
    let observation = RuntimeObservation::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    validate_runtime_observation_shape(&observation)?;
    if observation.runtime_handle.as_slice() != expected.runtime_handle()
        || observation
            .fence
            .as_option()
            .map(crate::validate_fence)
            .transpose()?
            .as_ref()
            != Some(expected.fence())
    {
        return Err(ProtocolValidationError::InvalidField(
            "runtime observation request binding",
        ));
    }
    Ok(())
}

pub(super) fn validate_runtime_inventory(body: &[u8]) -> Result<(), ProtocolValidationError> {
    let inventory = InventoryRuntimeResponse::decode_from_slice(body)
        .map_err(|error| ProtocolValidationError::MalformedWire(error.to_string()))?;
    if !inventory.__buffa_unknown_fields.is_empty() || inventory.runtimes.len() > 16_384 {
        return Err(ProtocolValidationError::UnknownFields);
    }
    let mut prior_handle: Option<&[u8]> = None;
    for observation in &inventory.runtimes {
        validate_runtime_observation_shape(observation)?;
        if prior_handle.is_some_and(|prior| prior >= observation.runtime_handle.as_slice()) {
            return Err(ProtocolValidationError::InvalidField(
                "runtime inventory order",
            ));
        }
        prior_handle = Some(&observation.runtime_handle);
    }
    if inventory.encode_to_vec() != body {
        return Err(ProtocolValidationError::UnknownFields);
    }
    Ok(())
}

fn validate_runtime_observation_shape(
    observation: &RuntimeObservation,
) -> Result<(), ProtocolValidationError> {
    let state = observation
        .state
        .as_known()
        .filter(|state| *state != RuntimeState::RUNTIME_STATE_UNSPECIFIED)
        .ok_or(ProtocolValidationError::InvalidField("runtime observation"))?;
    let error = observation.error.as_option();
    if !observation.__buffa_unknown_fields.is_empty()
        || observation.observation_sequence == 0
        || (state == RuntimeState::RUNTIME_STATE_FAILED) != error.is_some()
    {
        return Err(ProtocolValidationError::InvalidField("runtime observation"));
    }
    if let Some(error) = error {
        validate_embedded_error(error)?;
    }
    crate::exact_nonzero::<32>(&observation.runtime_handle, "runtime_handle")?;
    if !observation.leader_handle.is_empty() {
        crate::exact_nonzero::<32>(&observation.leader_handle, "leader_handle")?;
    }
    let fence = observation
        .fence
        .as_option()
        .ok_or(ProtocolValidationError::MissingField("runtime fence"))?;
    crate::validate_fence(fence)?;
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
