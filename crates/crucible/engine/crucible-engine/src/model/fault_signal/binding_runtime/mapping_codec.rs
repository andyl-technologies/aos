//! Canonical identities for resolved binding values and mapping outputs.

use super::super::*;
use super::{BindingRuntimeError, hex_bytes, reserve_usize_runtime};

pub(super) fn mapped_values_digest(
    values: &[SignalValue],
    resource_limits: FaultResourceLimits,
) -> Result<ContentHash, BindingRuntimeError> {
    let mut bytes = Vec::new();
    for value in values {
        let encoded = encode_signal_value(value).map_err(BindingRuntimeError::Trace)?;
        let requested = 4_usize
            .checked_add(encoded.len())
            .ok_or(BindingRuntimeError::MappedValueLimit)?;
        reserve_usize_runtime(
            resource_limits,
            "effect_payload_bytes",
            bytes.len(),
            requested,
        )?;
        bytes.extend_from_slice(
            &u32::try_from(encoded.len())
                .map_err(|_| BindingRuntimeError::MappedValueLimit)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&encoded);
    }
    Ok(ContentHash::from_canonical_material(
        "crucible.binding-mapped-values.v1",
        &hex_bytes(&bytes),
    ))
}

pub(super) fn resolved_mapping_output_digest(
    output: &ResolvedMappingOutput,
    resource_limits: FaultResourceLimits,
) -> Result<ContentHash, BindingRuntimeError> {
    let material = match output {
        ResolvedMappingOutput::Activation { active } => format!("activation={active}"),
        ResolvedMappingOutput::Parameter { parameter, value } => format!(
            "parameter={};value={}",
            mapped_parameter_name(*parameter),
            encoded_value_material(value)?,
        ),
        ResolvedMappingOutput::Hazard {
            probability_millionths,
        } => format!("hazard={probability_millionths}"),
        ResolvedMappingOutput::Impulse { event } => {
            format!("impulse={}", encoded_value_material(event)?)
        }
        ResolvedMappingOutput::StateTransition {
            transition_table,
            request,
            selected_transition,
        } => format!(
            "state_transition={};selected={};request={}",
            transition_table.as_str(),
            selected_transition.as_str(),
            encoded_value_material(request)?,
        ),
        ResolvedMappingOutput::ServiceProfile {
            service_profile,
            input_contracts,
            inputs,
        } => format!(
            "service_profile={};contracts={};inputs={}",
            service_profile.as_str(),
            mapped_service_inputs_digest(input_contracts, resource_limits)?.to_hex(),
            mapped_values_digest(inputs, resource_limits)?.to_hex(),
        ),
    };
    Ok(ContentHash::from_canonical_material(
        "crucible.resolved-binding-output.v1",
        &material,
    ))
}

fn mapped_service_inputs_digest(
    inputs: &[ServiceProfileInput],
    resource_limits: FaultResourceLimits,
) -> Result<ContentHash, BindingRuntimeError> {
    let mut material = b"crucible.resolved-binding-service-inputs.v1\0".to_vec();
    for input in inputs {
        let role = input.role.as_str().as_bytes();
        let role_length =
            u64::try_from(role.len()).map_err(|_| BindingRuntimeError::MappedValueLimit)?;
        material.extend_from_slice(&role_length.to_be_bytes());
        material.extend_from_slice(role);
        let encoded = encode_signal_shape(&input.shape).map_err(BindingRuntimeError::Trace)?;
        let length =
            u64::try_from(encoded.len()).map_err(|_| BindingRuntimeError::MappedValueLimit)?;
        material.extend_from_slice(&length.to_be_bytes());
        material.extend_from_slice(&encoded);
        reserve_usize_runtime(resource_limits, "effect_payload_bytes", 0, material.len())?;
    }
    Ok(ContentHash::from_bytes(&material))
}

fn encoded_value_material(value: &SignalValue) -> Result<String, BindingRuntimeError> {
    encode_signal_value(value)
        .map(|bytes| hex_bytes(&bytes))
        .map_err(BindingRuntimeError::Trace)
}

const fn mapped_parameter_name(parameter: MappedEffectParameter) -> &'static str {
    match parameter {
        MappedEffectParameter::Probability => "probability",
        MappedEffectParameter::DurationNanos => "duration_nanos",
        MappedEffectParameter::BitsPerSecond => "bits_per_second",
        MappedEffectParameter::BytesPerSecond => "bytes_per_second",
        MappedEffectParameter::OperationsPerSecond => "operations_per_second",
        MappedEffectParameter::CapacityRatio => "capacity_ratio",
        MappedEffectParameter::SignedOffset => "signed_offset",
        MappedEffectParameter::UnsignedCount => "unsigned_count",
    }
}
