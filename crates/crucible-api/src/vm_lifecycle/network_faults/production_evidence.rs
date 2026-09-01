//! Emits exact per-kind production conformance rows from causal tests.

use std::io::Write as _;

pub(in crate::vm_lifecycle) fn record_production_effect_rows(
    effects: &[crucible::model::EffectKind],
    case_id: &str,
    evidence: &str,
) {
    let Some(path) = std::env::var_os("CRUCIBLE_NETWORK_PRODUCTION_EFFECT_ROWS") else {
        return;
    };
    let registry = super::fault_implementation::network_effect_implementation_registry()
        .unwrap_or_else(|error| panic!("production network registry must validate: {error}"));
    let mut output = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|error| panic!("open production network evidence output: {error}"));
    for effect in effects {
        registry
            .require_implemented(*effect)
            .unwrap_or_else(|error| panic!("network effect row must be implemented: {error}"));
        writeln!(
            output,
            "production_effect_row={}|{}|gate:live-network-io|production-host-network-runtime|{}",
            effect.as_str(),
            case_id,
            evidence,
        )
        .unwrap_or_else(|error| panic!("write production network evidence row: {error}"));
    }
}
