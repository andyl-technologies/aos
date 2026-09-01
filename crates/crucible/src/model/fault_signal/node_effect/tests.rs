//! Node-effect contract regressions.

use super::*;
use crate::model::CountLimit;
use serde_json::json;

#[test]
fn nonpositive_cpu_capacity_is_rejected() {
    let capacity = match ExactRatio::new(0, 1) {
        Ok(value) => value,
        Err(error) => panic!("zero ratio is canonical: {error}"),
    };
    let quantum = match PositiveU64::new("quantum_instructions", 1) {
        Ok(value) => value,
        Err(error) => panic!("test quantum must be valid: {error}"),
    };
    let effect = NodeEffectSpecification::CpuService {
        vcpus: vec![0],
        capacity,
        quantum_instructions: quantum,
        service_rule: CpuServiceDiscipline::WorkConserving,
    };
    assert_eq!(effect.kind(), EffectKind::CpuService);
    assert!(effect.validate().is_err());
}

#[test]
fn register_transform_requires_exact_selected_width() {
    let register = match FaultObjectId::parse("rax") {
        Ok(value) => value,
        Err(error) => panic!("test register must be valid: {error}"),
    };
    let bit_count = match BoundedCount::new(CountLimit::RegisterBits, 64) {
        Ok(value) => value,
        Err(error) => panic!("test bit count must be valid: {error}"),
    };
    let short_mask = match HexBytes::parse("ff", 8) {
        Ok(value) => value,
        Err(error) => panic!("test mask must be valid: {error}"),
    };
    let effect = NodeEffectSpecification::RegisterTransform {
        register,
        first_bit: 0,
        bit_count,
        mutation: RegisterMutation::BitFlip { mask: short_mask },
        occurrence: NodeOccurrencePolicy::Every,
    };
    assert!(effect.validate().is_err());
}

#[test]
fn clock_drift_requires_positive_ratio() {
    let effect: NodeEffectSpecification = serde_json::from_value(json!({
        "kind": "clock_transform",
        "parameters": {
            "source": "clock-main",
            "mutation": {"kind": "drift", "parameters": {"ratio": {"numerator": -1, "denominator": 2}}},
            "monotonicity": "allow_backward",
            "overdue_timer_policy": "fire_at_boundary"
        }
    }))
    .unwrap_or_else(|error| panic!("negative reduced ratio must decode: {error}"));
    assert!(effect.validate().is_err());
}

#[test]
fn read_corruption_requires_a_read_access_class() {
    let effect: NodeEffectSpecification = serde_json::from_value(json!({
        "kind": "memory_access_transform",
        "parameters": {
            "range": {"start": 0, "length": 1},
            "accesses": {"fetch": false, "cpu_load": false, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
            "violate_atomicity": false,
            "mutation": {"kind": "read_corrupt", "parameters": {"mask": "01"}},
            "occurrence": {"kind": "every"}
        }
    }))
    .unwrap_or_else(|error| panic!("closed memory effect must decode: {error}"));
    assert!(effect.validate().is_err());
}

#[test]
fn access_specific_memory_mutations_reject_mixed_classes() {
    let read_corrupt: NodeEffectSpecification = serde_json::from_value(json!({
        "kind": "memory_access_transform",
        "parameters": {
            "range": {"start": 0, "length": 1},
            "accesses": {"fetch": false, "cpu_load": true, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
            "violate_atomicity": false,
            "mutation": {"kind": "read_corrupt", "parameters": {"mask": "01"}},
            "occurrence": {"kind": "every"}
        }
    }))
    .unwrap_or_else(|error| panic!("closed read mutation must decode: {error}"));
    let lost_write: NodeEffectSpecification = serde_json::from_value(json!({
        "kind": "memory_access_transform",
        "parameters": {
            "range": {"start": 0, "length": 1},
            "accesses": {"fetch": false, "cpu_load": true, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
            "violate_atomicity": false,
            "mutation": {"kind": "lost_write"},
            "occurrence": {"kind": "every"}
        }
    }))
    .unwrap_or_else(|error| panic!("closed write mutation must decode: {error}"));

    assert!(read_corrupt.validate().is_err());
    assert!(lost_write.validate().is_err());
}

#[test]
fn torn_write_requires_a_nontrivial_selector() {
    for selector in ["00", "ff"] {
        let effect: NodeEffectSpecification = serde_json::from_value(json!({
            "kind": "memory_access_transform",
            "parameters": {
                "range": {"start": 0, "length": 1},
                "accesses": {"fetch": false, "cpu_load": false, "cpu_store": true, "dma_read": false, "dma_write": false, "page_table_walk": false},
                "violate_atomicity": true,
                "mutation": {"kind": "torn_write", "parameters": {"selector": selector}},
                "occurrence": {"kind": "every"}
            }
        }))
        .unwrap_or_else(|error| panic!("closed memory effect must decode: {error}"));
        assert!(effect.validate().is_err());
    }
}
