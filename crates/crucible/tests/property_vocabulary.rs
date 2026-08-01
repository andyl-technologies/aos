//! Checks T-ASRT-1 property vocabulary shape and schema versioning.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, Condition, EngineError, PROPERTY_QUANTIFIER_COUNT,
    PROPERTY_SCHEMA_DOMAIN, PROPERTY_SCHEMA_VERSION, Predicate, Properties, Property, PropertyKind,
    ReachabilityExpectation, ReachableDisposition, VirtualTime, World,
};

#[test]
fn property_vocabulary_is_closed_and_versioned() {
    assert_eq!(PROPERTY_SCHEMA_VERSION, 1);
    assert_eq!(PROPERTY_SCHEMA_DOMAIN, "crucible.model.properties.v1");
    assert_eq!(PROPERTY_QUANTIFIER_COUNT, 5);
    assert_eq!(
        PropertyKind::ALL,
        [
            PropertyKind::Always,
            PropertyKind::Sometimes,
            PropertyKind::Eventually,
            PropertyKind::AfterQuiescence,
            PropertyKind::Reachable,
        ]
    );
    assert_eq!(
        PropertyKind::ALL.map(PropertyKind::binary_tag),
        [0, 1, 2, 3, 4]
    );
    assert_eq!(
        PropertyKind::ALL.map(PropertyKind::canonical_label),
        [
            "always",
            "sometimes",
            "eventually",
            "after-quiescence",
            "reachable",
        ]
    );
    assert_eq!(
        PropertyKind::ALL.map(PropertyKind::toml_kind),
        [
            "always",
            "sometimes",
            "eventually",
            "after_quiescence",
            "reachable",
        ]
    );
    for kind in PropertyKind::ALL {
        assert_eq!(PropertyKind::from_binary_tag(kind.binary_tag()), Some(kind));
        assert_eq!(PropertyKind::from_toml_kind(kind.toml_kind()), Some(kind));
    }
    assert_eq!(
        PropertyKind::from_binary_tag(PROPERTY_QUANTIFIER_COUNT as u8),
        None
    );
    assert_eq!(PropertyKind::from_toml_kind("forall"), None);
}

#[test]
fn all_property_quantifiers_round_trip_through_versioned_properties_schema() {
    let world = empty_world();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![
            assertion(
                "00-always",
                Property::Always {
                    predicate: Predicate::quiescent(),
                },
            ),
            assertion(
                "01-sometimes",
                Property::Sometimes {
                    predicate: Predicate::named("leader-elected"),
                },
            ),
            assertion(
                "02-eventually",
                Property::Eventually {
                    trigger: Predicate::named("request-started"),
                    property: Predicate::named("response-committed"),
                    deadline: VirtualTime { ticks: 25 },
                },
            ),
            assertion(
                "03-after-quiescence",
                Property::AfterQuiescence {
                    predicate: Predicate::quiescent(),
                },
            ),
            assertion(
                "04-reachable-warn",
                Property::Reachable {
                    predicate: Predicate::named("rare-branch"),
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Warn,
                    },
                },
            ),
            assertion(
                "05-reachable-fail",
                Property::Reachable {
                    predicate: Predicate::named("must-hit-branch"),
                    expectation: ReachabilityExpectation::Reachable {
                        on_unreached: ReachableDisposition::Fail,
                    },
                },
            ),
            assertion(
                "06-unreachable-dual",
                Property::Reachable {
                    predicate: Predicate::named("forbidden-branch"),
                    expectation: ReachabilityExpectation::Unreachable,
                },
            ),
        ],
    )
    .unwrap_or_else(|error| panic!("closed vocabulary properties should validate: {error}"));

    assert_eq!(
        properties
            .assertions()
            .iter()
            .map(|assertion| assertion.property.kind())
            .collect::<Vec<_>>(),
        vec![
            PropertyKind::Always,
            PropertyKind::Sometimes,
            PropertyKind::Eventually,
            PropertyKind::AfterQuiescence,
            PropertyKind::Reachable,
            PropertyKind::Reachable,
            PropertyKind::Reachable,
        ]
    );

    let canonical = String::from_utf8(properties.canonical_bytes())
        .unwrap_or_else(|error| panic!("canonical properties bytes should be UTF-8: {error}"));
    for kind in PropertyKind::ALL {
        assert!(
            canonical.contains(&format!("property={}", kind.canonical_label())),
            "canonical properties material must name {:?}",
            kind
        );
    }
    assert!(canonical.contains("expectation=unreachable"));
    assert!(canonical.contains("on_unreached=warn"));
    assert!(canonical.contains("on_unreached=fail"));

    let toml = properties
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("properties TOML should serialize: {error}"));
    for kind in PropertyKind::ALL {
        assert!(
            toml.contains(&format!("kind = \"{}\"", kind.toml_kind())),
            "properties TOML must name {:?} using the closed kind string",
            kind
        );
    }
    let from_toml = Properties::from_canonical_toml_for_world(&world, &toml)
        .unwrap_or_else(|error| panic!("properties TOML should parse: {error}"));
    let binary = properties.to_compact_binary();
    let from_binary = Properties::from_compact_binary_for_world(&world, &binary)
        .unwrap_or_else(|error| panic!("properties binary should parse: {error}"));

    assert_eq!(from_toml, properties);
    assert_eq!(from_binary, properties);
    assert_eq!(binary_prefix(&binary), b"crucible.properties.v1\0");
}

#[test]
fn property_toml_rejects_unknown_quantifier_kind() {
    let world = empty_world();
    let input = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[assertion]]
id = "bad"
message = "must be rejected"

[assertion.property]
kind = "forall"

[assertion.property.predicate]
kind = "quiescent"
"#;

    let error = Properties::from_canonical_toml_for_world(&world, input)
        .expect_err("unknown property quantifier must be rejected");
    assert!(
        matches!(
            error,
            EngineError::ScenarioSerialization { ref reason }
                if reason == "invalid property kind `forall`"
        ),
        "unknown property quantifier must fail before id validation: {error}"
    );
}

#[test]
fn property_toml_enforces_quantifier_specific_fields() {
    let world = empty_world();
    let always_with_deadline = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[assertion]]
id = "bad"
message = "must be rejected"

[assertion.property]
kind = "always"
deadline_ticks = 10

[assertion.property.predicate]
kind = "quiescent"
"#;
    let missing_reachability_expectation = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[assertion]]
id = "bad"
message = "must be rejected"

[assertion.property]
kind = "reachable"

[assertion.property.predicate]
kind = "quiescent"
"#;

    let error = Properties::from_canonical_toml_for_world(&world, always_with_deadline)
        .expect_err("always property must reject eventually-only fields");
    assert!(
        matches!(
            error,
            EngineError::ScenarioSerialization { ref reason }
                if reason == "property kind `always` has unexpected `deadline_ticks`"
        ),
        "always property must reject eventually-only fields before id validation: {error}"
    );
    let error = Properties::from_canonical_toml_for_world(&world, missing_reachability_expectation)
        .expect_err("reachable property must require an expectation");
    assert!(
        matches!(
            error,
            EngineError::ScenarioSerialization { ref reason }
                if reason == "property kind `reachable` missing `expectation`"
        ),
        "reachable property must require expectation before id validation: {error}"
    );
}

#[test]
fn assertions_and_triggers_share_one_condition_type() {
    let condition: Condition = Predicate::named("shared-condition");
    let property = Property::Always {
        predicate: condition.clone(),
    };

    assert_eq!(property.kind(), PropertyKind::Always);
    assert_eq!(
        property_predicates(&property),
        vec![&condition],
        "assertion properties must carry the shared trigger Condition type"
    );
}

fn property_predicates(property: &Property) -> Vec<&Predicate> {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::AfterQuiescence { predicate }
        | Property::Reachable { predicate, .. } => vec![predicate],
        Property::Eventually {
            trigger, property, ..
        } => vec![trigger, property],
    }
}

fn assertion(id: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: format!("{id} property"),
        property,
    }
}

fn empty_world() -> World {
    World::from_nodes(Vec::new()).expect("empty world should build")
}

fn binary_prefix(binary: &[u8]) -> &[u8] {
    let end = b"crucible.properties.v1\0".len();
    &binary[..end]
}
