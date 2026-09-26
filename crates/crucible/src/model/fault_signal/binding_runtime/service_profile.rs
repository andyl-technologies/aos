//! Service-profile identity regression.

use super::*;

#[test]
fn service_profile_identity_includes_named_physical_input_contracts() {
    let value = SignalValue::U64(42);
    let distance = ResolvedMappingOutput::ServiceProfile {
        service_profile: object_id("physical-input-profile"),
        input_contracts: vec![ServiceProfileInput {
            role: object_id("distance"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::Millimetres, 0)
                .unwrap_or_else(|error| panic!("distance shape: {error}")),
        }],
        inputs: vec![value.clone()],
    };
    let count = ResolvedMappingOutput::ServiceProfile {
        service_profile: object_id("physical-input-profile"),
        input_contracts: vec![ServiceProfileInput {
            role: object_id("count"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::Dimensionless, 0)
                .unwrap_or_else(|error| panic!("count shape: {error}")),
        }],
        inputs: vec![value],
    };
    let range = ResolvedMappingOutput::ServiceProfile {
        service_profile: object_id("physical-input-profile"),
        input_contracts: vec![ServiceProfileInput {
            role: object_id("range"),
            shape: SignalShape::new(SignalValueType::U64, SignalUnit::Millimetres, 0)
                .unwrap_or_else(|error| panic!("range shape: {error}")),
        }],
        inputs: vec![SignalValue::U64(42)],
    };

    let distance_digest = resolved_mapping_output_digest(&distance, FaultResourceLimits::default())
        .unwrap_or_else(|error| panic!("distance digest: {error}"));
    assert_ne!(
        distance_digest,
        resolved_mapping_output_digest(&count, FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("count digest: {error}")),
    );
    assert_ne!(
        distance_digest,
        resolved_mapping_output_digest(&range, FaultResourceLimits::default())
            .unwrap_or_else(|error| panic!("range digest: {error}")),
    );
}
