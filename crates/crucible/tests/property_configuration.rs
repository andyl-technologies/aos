//! Checks T-ASRT-3 per-quantifier property configuration.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    AssertionDef, AssertionId, EngineError, Predicate, Properties, Property,
    ReachabilityExpectation, ReachableDisposition, VirtualTime, World,
};

#[test]
fn property_configuration_is_canonical_and_hash_affecting() {
    let world = empty_world();
    let eventual_id = "eventual-settle";
    let eventual_message = "cluster settles by virtual tick 42";
    let configured_properties = properties(
        &world,
        vec![
            assertion(
                eventual_id,
                eventual_message,
                Property::Eventually {
                    trigger: Predicate::quiescent(),
                    property: Predicate::named("cluster-settled"),
                    deadline: VirtualTime { ticks: 42 },
                },
            ),
            assertion(
                "coverage-warn",
                "warn if the rare branch is never reached",
                reachable("rare-branch", ReachableDisposition::Warn),
            ),
            assertion(
                "coverage-fail",
                "fail if the required branch is never reached",
                reachable("required-branch", ReachableDisposition::Fail),
            ),
            assertion(
                "forbidden-branch",
                "the forbidden branch remains unreachable",
                Property::Reachable {
                    predicate: Predicate::named("forbidden-branch"),
                    expectation: ReachabilityExpectation::Unreachable,
                },
            ),
        ],
    );

    let canonical = canonical_text(&configured_properties);
    assert!(
        canonical.contains(&format!(
            "assertion_id_len={}\nassertion_id={eventual_id}",
            eventual_id.len()
        )),
        "stable assertion id must be canonical material"
    );
    assert!(
        canonical.contains(&format!(
            "message_len={}\nmessage={eventual_message}",
            eventual_message.len()
        )),
        "human-readable assertion message must be canonical material"
    );
    assert!(canonical.contains("property=eventually"));
    assert!(canonical.contains("deadline_ticks=42"));
    assert!(canonical.contains("trigger:\npredicate=quiescent"));
    assert!(canonical.contains("property_predicate:\npredicate=named"));
    assert!(canonical.contains("property=reachable"));
    assert!(canonical.contains("expectation=reachable\non_unreached=warn"));
    assert!(canonical.contains("expectation=reachable\non_unreached=fail"));
    assert!(canonical.contains("expectation=unreachable"));

    assert_hash_moves(
        properties(
            &world,
            vec![assertion(eventual_id, eventual_message, eventual(42))],
        ),
        properties(
            &world,
            vec![assertion(
                "eventual-settle-renamed",
                eventual_message,
                eventual(42),
            )],
        ),
        "stable assertion id must affect properties identity",
    );
    assert_hash_moves(
        properties(
            &world,
            vec![assertion(eventual_id, eventual_message, eventual(42))],
        ),
        properties(
            &world,
            vec![assertion(
                eventual_id,
                "cluster settles by a different message",
                eventual(42),
            )],
        ),
        "assertion message must affect properties identity",
    );
    assert_hash_moves(
        properties(
            &world,
            vec![assertion(eventual_id, eventual_message, eventual(42))],
        ),
        properties(
            &world,
            vec![assertion(eventual_id, eventual_message, eventual(43))],
        ),
        "Eventually virtual-time deadline must affect properties identity",
    );
    assert_hash_moves(
        properties(
            &world,
            vec![assertion(
                "coverage-disposition",
                "coverage disposition",
                reachable("rare-branch", ReachableDisposition::Warn),
            )],
        ),
        properties(
            &world,
            vec![assertion(
                "coverage-disposition",
                "coverage disposition",
                reachable("rare-branch", ReachableDisposition::Fail),
            )],
        ),
        "Reachable never-reached disposition must affect properties identity",
    );
    assert_hash_moves(
        properties(
            &world,
            vec![assertion(
                "coverage-expectation",
                "coverage expectation",
                reachable("rare-branch", ReachableDisposition::Warn),
            )],
        ),
        properties(
            &world,
            vec![assertion(
                "coverage-expectation",
                "coverage expectation",
                Property::Reachable {
                    predicate: Predicate::named("rare-branch"),
                    expectation: ReachabilityExpectation::Unreachable,
                },
            )],
        ),
        "Reachable ordinary/unreachable dual must affect properties identity",
    );
}

#[test]
fn property_configuration_round_trips_through_toml_and_binary() {
    let world = empty_world();
    let properties = properties(
        &world,
        vec![
            assertion(
                "eventual-round-trip",
                "eventual configuration round trip",
                eventual(64),
            ),
            assertion(
                "reachable-warn-round-trip",
                "reachable warn configuration round trip",
                reachable("warn-marker", ReachableDisposition::Warn),
            ),
            assertion(
                "reachable-fail-round-trip",
                "reachable fail configuration round trip",
                reachable("fail-marker", ReachableDisposition::Fail),
            ),
            assertion(
                "unreachable-round-trip",
                "unreachable dual configuration round trip",
                Property::Reachable {
                    predicate: Predicate::named("forbidden-marker"),
                    expectation: ReachabilityExpectation::Unreachable,
                },
            ),
        ],
    );

    let toml = properties
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("property configuration TOML should serialize: {error}"));
    let from_toml = Properties::from_canonical_toml_for_world(&world, &toml)
        .unwrap_or_else(|error| panic!("property configuration TOML should parse: {error}"));
    let binary = properties.to_compact_binary();
    let from_binary = Properties::from_compact_binary_for_world(&world, &binary)
        .unwrap_or_else(|error| panic!("property configuration binary should parse: {error}"));

    assert_eq!(from_toml, properties);
    assert_eq!(from_binary, properties);
    assert_eq!(from_toml.content_hash(), properties.content_hash());
    assert_eq!(from_binary.content_hash(), properties.content_hash());
}

#[test]
fn reachable_toml_defaults_never_reached_disposition_to_warn() {
    let world = empty_world();
    let explicit_warn = properties(
        &world,
        vec![assertion(
            "reachable-default-warn",
            "reachable defaults to warn",
            reachable("default-warn-marker", ReachableDisposition::Warn),
        )],
    );
    let explicit_toml = explicit_warn
        .to_canonical_toml()
        .unwrap_or_else(|error| panic!("explicit warn TOML should serialize: {error}"));
    let defaulted_toml = explicit_toml.replace("on_unreached = \"warn\"\n", "");

    assert_ne!(
        defaulted_toml, explicit_toml,
        "test fixture must remove the explicit reachable warn disposition"
    );
    assert!(!defaulted_toml.contains("on_unreached"));

    let defaulted = Properties::from_canonical_toml_for_world(&world, &defaulted_toml)
        .unwrap_or_else(|error| panic!("omitted reachable disposition should parse: {error}"));

    assert_eq!(defaulted, explicit_warn);
    assert_eq!(defaulted.content_hash(), explicit_warn.content_hash());
}

#[test]
fn scenario_validation_rejects_wall_clock_and_nondeterministic_property_parameters() {
    let world = empty_world();
    for (field, input) in [
        (
            "deadline_seconds",
            forbidden_eventually_toml("deadline_seconds", "5"),
        ),
        (
            "deadline_wall_clock_seconds",
            forbidden_eventually_toml("deadline_wall_clock_seconds", "5"),
        ),
        (
            "deadline_from_system_time",
            forbidden_eventually_toml("deadline_from_system_time", "true"),
        ),
    ] {
        assert_toml_error_contains(
            &world,
            &input,
            field,
            "wall-clock and nondeterministic property parameters must be rejected before id validation",
        );
    }
}

#[test]
fn scenario_validation_rejects_unknown_reachable_dispositions() {
    let world = empty_world();
    let input = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[assertion]]
id = "reachable-invalid-disposition"
message = "invalid reachable disposition"

[assertion.property]
kind = "reachable"

[assertion.property.predicate]
kind = "named"
name = "invalid-marker"

[assertion.property.expectation]
kind = "reachable"
on_unreached = "panic"
"#;

    assert_toml_error_contains(
        &world,
        input,
        "panic",
        "unknown reachable never-reached dispositions must be rejected",
    );
}

fn assert_hash_moves(baseline: Properties, changed: Properties, message: &'static str) {
    assert_ne!(baseline.content_hash(), changed.content_hash(), "{message}");
}

fn assert_toml_error_contains(world: &World, input: &str, expected: &str, message: &'static str) {
    let error = Properties::from_canonical_toml_for_world(world, input)
        .expect_err("invalid property configuration must be rejected");
    assert!(
        matches!(
            error,
            EngineError::ScenarioSerialization { ref reason }
                if reason.contains(expected)
        ),
        "{message}: expected `{expected}` in error, got {error}"
    );
}

fn forbidden_eventually_toml(field: &str, value: &str) -> String {
    format!(
        r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"

[[assertion]]
id = "eventually-forbidden-parameter"
message = "forbidden eventually parameter"

[assertion.property]
kind = "eventually"
deadline_ticks = 50
{field} = {value}

[assertion.property.trigger]
kind = "quiescent"

[assertion.property.property]
kind = "named"
name = "eventual-marker"
"#
    )
}

fn properties(world: &World, assertions: Vec<AssertionDef>) -> Properties {
    Properties::from_assertions_for_world(world, assertions)
        .unwrap_or_else(|error| panic!("properties should validate: {error}"))
}

fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: message.to_owned(),
        property,
    }
}

fn eventual(deadline_ticks: u64) -> Property {
    Property::Eventually {
        trigger: Predicate::quiescent(),
        property: Predicate::named("cluster-settled"),
        deadline: VirtualTime {
            ticks: deadline_ticks,
        },
    }
}

fn reachable(name: &str, on_unreached: ReachableDisposition) -> Property {
    Property::Reachable {
        predicate: Predicate::named(name),
        expectation: ReachabilityExpectation::Reachable { on_unreached },
    }
}

fn canonical_text(properties: &Properties) -> String {
    String::from_utf8(properties.canonical_bytes())
        .unwrap_or_else(|error| panic!("canonical properties bytes should be UTF-8: {error}"))
}

fn empty_world() -> World {
    World::from_nodes(Vec::new()).expect("empty world should build")
}
