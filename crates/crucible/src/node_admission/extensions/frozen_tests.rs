//! Tests exact immutable typed semantic retention without native qualification.

// crucible-lint: allow panic-shortcut -- These frozen tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crucible_node_contract::{HashRef, SemanticVersion, U64, canonical};

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

fn reference(value: &[u8]) -> ContentRef {
    canonical::content_ref(value, "text/plain").unwrap()
}

fn selection() -> ExtensionSelection {
    ExtensionSelection {
        declaration: reference(b"model-only declaration"),
        identifier: id("model/frozen"),
        semantic_version: SemanticVersion {
            major: U64::new(1),
            minor: U64::new(0),
            patch: U64::new(0),
            prerelease: None,
            build: None,
        },
        schema_digest: reference(b"model-only schema").hash,
    }
}

fn contract() -> ExtensionSemanticContract {
    let body = reference(b"model-only exact semantic axes; no native qualification");
    ExtensionSemanticContract {
        class_contract: body.clone(),
        facet_contract: body.clone(),
        mode_contract: body.clone(),
        port_contract: body.clone(),
        timing_contract: body.clone(),
        state_contract: body.clone(),
        error_contract: body.clone(),
        qualification_contract: body,
        locations: BTreeSet::from([ExtensionRecordKind::WorldBinding]),
        roles: BTreeSet::new(),
        facets: BTreeSet::new(),
        modes: vec![],
        interfaces: BTreeSet::new(),
        impact: ExtensionImpact::Metadata,
    }
}

fn identity(contract: ExtensionSemanticContract) -> HashRef {
    canonical::json_hash(
        "cnp.frozen-definition-test.v2",
        &AdmittedExtensionDefinition::new(selection(), reference(b"handler"), contract),
    )
    .unwrap()
}

#[test]
fn every_typed_effect_and_selector_axis_changes_the_frozen_identity() {
    let baseline = identity(contract());
    let changed = reference(b"another actual contract body");
    for axis in 0..14 {
        let mut actual = contract();
        match axis {
            0 => actual.class_contract = changed.clone(),
            1 => actual.facet_contract = changed.clone(),
            2 => actual.mode_contract = changed.clone(),
            3 => actual.port_contract = changed.clone(),
            4 => actual.timing_contract = changed.clone(),
            5 => actual.state_contract = changed.clone(),
            6 => actual.error_contract = changed.clone(),
            7 => actual.qualification_contract = changed.clone(),
            8 => actual.locations = BTreeSet::from([ExtensionRecordKind::NodeDescriptor]),
            9 => actual.roles = BTreeSet::from([id("clock")]),
            10 => actual.facets = BTreeSet::from([id("model/execution")]),
            11 => actual.modes = vec![OperatingMode::Exact],
            12 => actual.interfaces = BTreeSet::from([id("model/interface")]),
            13 => actual.impact = ExtensionImpact::Behavior,
            _ => unreachable!(),
        }
        assert_ne!(identity(actual), baseline, "axis {axis}");
    }
}

#[test]
fn later_mutable_installation_defaults_do_not_change_frozen_source_contracts() {
    let mut current = contract();
    let frozen =
        AdmittedExtensionDefinition::new(selection(), reference(b"handler"), current.clone());
    let original = serde_json::to_value(&frozen).unwrap();

    current.impact = ExtensionImpact::Behavior;
    current.class_contract = reference(b"replacement default");
    current.roles.insert(id("replacement-role"));

    assert_eq!(serde_json::to_value(&frozen).unwrap(), original);
    assert_eq!(frozen.semantic_contract().impact, ExtensionImpact::Metadata);
    assert_ne!(frozen.semantic_contract(), &current);
    assert_eq!(frozen.selection(), &selection());
    assert_eq!(frozen.handler_identity(), &reference(b"handler"));
}
