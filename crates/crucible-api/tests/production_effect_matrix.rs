//! Executed production-conformance matrix for every advertised fault effect.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crucible::model::{EffectImplementationRegistry, EffectKind, FaultAdapter};

#[test]
fn every_advertised_effect_is_bound_to_production_and_live_gate_evidence()
-> Result<(), Box<dyn Error>> {
    let registries = [
        crucible_api::vm_lifecycle::network_effect_implementation_registry()?,
        crucible_api::vm_lifecycle::storage_effect_implementation_registry()?,
        crucible_qemu::node_effect_implementation_registry()?,
    ];
    let mut rows = BTreeMap::new();
    let mut adapters = BTreeSet::new();

    for registry in &registries {
        registry.require_complete()?;
        adapters.insert(registry.adapter());
        record_registry_rows(registry, &mut rows)?;
    }

    assert_eq!(
        adapters,
        BTreeSet::from([
            FaultAdapter::Network,
            FaultAdapter::Storage,
            FaultAdapter::Node,
        ])
    );
    assert_eq!(rows.len(), EffectKind::all().len());
    assert_eq!(
        rows.keys().copied().collect::<Vec<_>>(),
        EffectKind::all().iter().copied().collect::<Vec<_>>()
    );

    if let Ok(path) = std::env::var("CRUCIBLE_PRODUCTION_EFFECT_MATRIX_OUTPUT") {
        let contents = rows.values().cloned().collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(path, contents)?;
    }
    Ok(())
}

fn record_registry_rows(
    registry: &EffectImplementationRegistry,
    rows: &mut BTreeMap<EffectKind, String>,
) -> Result<(), Box<dyn Error>> {
    for contract in registry.contracts() {
        let conformance = contract.production_conformance;
        assert_eq!(contract.effect.descriptor().adapter, registry.adapter());
        assert_eq!(conformance.case_id, contract.effect.as_str());
        assert!(conformance.harness.contains("crucible"));
        assert!(!conformance.observed_state.is_empty());
        assert_live_gate_matches_adapter(contract.effect, conformance.live_gate);

        let forbidden = conformance.harness.to_ascii_lowercase();
        assert!(!forbidden.contains("test-double"));
        assert!(!forbidden.contains("mock"));
        assert!(!forbidden.contains("fake"));

        let row = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            contract.effect.as_str(),
            adapter_name(registry.adapter()),
            conformance.case_id,
            conformance.live_gate,
            conformance.harness,
            contract.executor,
            conformance.observed_state.join(","),
        );
        assert!(rows.insert(contract.effect, row).is_none());
    }
    Ok(())
}

fn assert_live_gate_matches_adapter(effect: EffectKind, live_gate: &str) {
    match effect.descriptor().adapter {
        FaultAdapter::Network => assert_eq!(live_gate, "gate:live-network-io"),
        FaultAdapter::Storage => match effect {
            EffectKind::NinePResult | EffectKind::NinePVisibility => {
                assert_eq!(live_gate, "gate:live-9p-io");
            }
            _ => assert_eq!(live_gate, "gate:live-block-io"),
        },
        FaultAdapter::Node => assert!(matches!(
            live_gate,
            "gate:live-node-lifecycle-fault" | "gate:live-fault-hardware" | "gate:patch-microtests"
        )),
    }
}

const fn adapter_name(adapter: FaultAdapter) -> &'static str {
    match adapter {
        FaultAdapter::Network => "network",
        FaultAdapter::Storage => "storage",
        FaultAdapter::Node => "node",
    }
}
