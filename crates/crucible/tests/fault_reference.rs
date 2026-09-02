//! User-reference completeness checks for the closed fault vocabulary.

use std::collections::BTreeMap;

use crucible::model::{
    EffectKind, FaultOperation, FaultTargetKind, PureSignalOperator, SignalSourceKind,
    StatefulSignalOperator,
};

const REFERENCE: &str = include_str!("../../../docs/users/crucible/reference.md");
const GUIDE_INDEX: &str = include_str!("../../../docs/users/crucible/README.md");
const NETWORK_GUIDE: &str = include_str!("../../../docs/users/crucible/network-faults.md");
const STORAGE_NODE_GUIDE: &str =
    include_str!("../../../docs/users/crucible/storage-node-faults.md");
const SIGNAL_GUIDE: &str = include_str!("../../../docs/users/crucible/signals.md");
const BINDING_GUIDE: &str = include_str!("../../../docs/users/crucible/bindings.md");
const TOPOLOGY_GUIDE: &str = include_str!("../../../docs/users/crucible/topology.md");
const SIGNAL_DRIVEN_GUIDE: &str =
    include_str!("../../../docs/users/crucible/signal-driven-faults.md");

const USER_GUIDES: &[&str] = &[
    "authoring.md",
    "artifacts.md",
    "bindings.md",
    "ci.md",
    "coverage.md",
    "cookbook.md",
    "daemon.md",
    "debugging.md",
    "examples.md",
    "exploration.md",
    "fault-model-migration.md",
    "network-faults.md",
    "quickstart.md",
    "properties-and-evidence.md",
    "recorded-signals.md",
    "reference.md",
    "reproduction.md",
    "running.md",
    "rust-api.md",
    "scenarios.md",
    "signal-driven-faults.md",
    "signals.md",
    "storage-node-faults.md",
    "support.md",
    "topology.md",
    "troubleshooting.md",
];

#[test]
fn every_executable_effect_has_exactly_one_reference_row() {
    assert_exact_reference_rows(
        section(
            "### Exhaustive effect registry",
            "## Properties and predicates",
        ),
        EffectKind::all().iter().map(|kind| kind.as_str()),
        "effect",
    );
}

#[test]
fn every_signal_and_target_registry_value_has_exactly_one_reference_row() {
    assert_exact_reference_rows(
        section("Signal source kinds are exhaustive:", "Interpolation is"),
        SignalSourceKind::all().iter().map(|kind| kind.as_str()),
        "signal source",
    );
    assert_exact_reference_rows(
        section(
            "The `operator` field is exhaustive:",
            "Stateful specification kinds are exhaustive:",
        ),
        PureSignalOperator::all().iter().map(|kind| kind.as_str()),
        "pure operator",
    );
    assert_exact_reference_rows(
        section(
            "Stateful specification kinds are exhaustive:",
            "Unknown variants or fields",
        ),
        StatefulSignalOperator::all()
            .iter()
            .map(|kind| kind.as_str()),
        "stateful operator",
    );
    assert_exact_reference_rows(
        section(
            "### Fault opportunity operation values",
            "### Target selector values",
        ),
        FaultOperation::all()
            .iter()
            .map(|operation| operation.as_str()),
        "fault operation",
    );
    assert_exact_reference_rows(
        section("### Target selector values", "Sensor targets are"),
        FaultTargetKind::all().iter().map(|kind| kind.as_str()),
        "target",
    );
}

#[test]
fn reference_tables_have_balanced_code_spans_and_columns() {
    let mut expected_columns = None;
    for (line_number, line) in REFERENCE.lines().enumerate() {
        if !line.starts_with('|') {
            expected_columns = None;
            continue;
        }
        assert_eq!(
            line.bytes().filter(|byte| *byte == b'`').count() % 2,
            0,
            "reference line {} has an unclosed code span",
            line_number + 1
        );
        let columns = markdown_table_columns(line);
        match expected_columns {
            None => expected_columns = Some(columns),
            Some(expected) => assert_eq!(
                columns,
                expected,
                "reference table line {} has {columns} columns, expected {expected}: {line}",
                line_number + 1
            ),
        }
    }
}

#[test]
fn guide_index_links_every_user_guide() {
    for guide in USER_GUIDES {
        assert!(
            GUIDE_INDEX.contains(&format!("]({guide})")),
            "Crucible guide index must link `{guide}`"
        );
    }
}

#[test]
fn domain_guides_name_every_executable_effect() {
    for effect in EffectKind::all() {
        let name = effect.as_str();
        let guide = if name.starts_with("network.") {
            NETWORK_GUIDE
        } else {
            STORAGE_NODE_GUIDE
        };
        assert!(
            guide.contains(&format!("`{name}`")),
            "task-oriented fault guide must name executable effect `{name}`"
        );
    }
}

#[test]
fn effect_guide_matrices_match_executable_descriptors() {
    for effect in EffectKind::all() {
        let name = effect.as_str();
        let guide = if name.starts_with("network.") {
            NETWORK_GUIDE
        } else {
            STORAGE_NODE_GUIDE
        };
        let row_prefix = format!("| `{name}` | ");
        let rows = guide
            .lines()
            .filter(|line| line.starts_with(&row_prefix))
            .collect::<Vec<_>>();
        assert_eq!(
            rows.len(),
            1,
            "effect guide must have one contract row for `{name}`"
        );

        let row = rows[0];
        let descriptor = effect.descriptor();
        assert!(
            row.contains(&format!("`{}`", descriptor.capability)),
            "contract row for `{name}` must name capability `{}`",
            descriptor.capability
        );
        for phase in descriptor.phases {
            assert!(
                row.contains(&format!("`{}`", phase.as_str())),
                "contract row for `{name}` must name phase `{}`",
                phase.as_str()
            );
        }
        for lifetime in descriptor.lifetimes {
            let lifetime = debug_variant_as_snake_case(lifetime);
            assert!(
                row.contains(&format!("`{lifetime}`")),
                "contract row for `{name}` must name lifetime `{lifetime}`"
            );
        }
        let composition = debug_variant_as_snake_case(&descriptor.composition);
        assert!(
            row.contains(&format!("`{composition}`")),
            "contract row for `{name}` must name composition `{composition}`"
        );
    }
}

#[test]
fn task_guides_cover_signal_and_binding_vocabularies() {
    for source in SignalSourceKind::all() {
        assert_code_name(SIGNAL_GUIDE, source.as_str(), "signal source");
    }
    for operator in PureSignalOperator::all() {
        assert_code_name(SIGNAL_GUIDE, operator.as_str(), "pure signal operator");
    }
    for operator in StatefulSignalOperator::all() {
        assert_code_name(SIGNAL_GUIDE, operator.as_str(), "stateful signal operator");
    }

    for mapping in [
        "active_when_true",
        "active_when_equal",
        "threshold",
        "map_parameter",
        "piecewise_parameter",
        "hazard",
        "impulse_on_event",
        "state_transition",
        "service_profile",
    ] {
        assert_code_name(BINDING_GUIDE, mapping, "binding mapping");
    }

    for effect in EffectKind::all() {
        let descriptor = effect.descriptor();
        for phase in descriptor.phases {
            assert_code_name(BINDING_GUIDE, phase.as_str(), "fault phase");
        }
        for lifetime in descriptor.lifetimes {
            assert_code_name(
                BINDING_GUIDE,
                &debug_variant_as_snake_case(lifetime),
                "effect lifetime",
            );
        }
        assert_code_name(
            BINDING_GUIDE,
            &debug_variant_as_snake_case(&descriptor.composition),
            "composition algebra",
        );
    }
}

#[test]
fn authoring_excerpt_uses_the_flattened_wire_shape() {
    for forbidden in [
        "[plan.signal.node]",
        "[plan.fault_binding.sampling]",
        "semantic_version = 1\nsignals =",
        "search_policy = { kind = \"fixed\" }",
    ] {
        assert!(
            !SIGNAL_DRIVEN_GUIDE.contains(forbidden),
            "signal authoring example must not use retired wire shape `{forbidden}`"
        );
    }
    for required in [
        "exported = true",
        "kind = \"constant\"",
        "sampling = \"at_boundary\"",
        "search = \"fixed\"",
    ] {
        assert!(
            SIGNAL_DRIVEN_GUIDE.contains(required),
            "signal authoring example must use canonical wire field `{required}`"
        );
    }
}

#[test]
fn signal_and_binding_reference_names_canonical_defaulted_fields() {
    for field in [
        "`exported` | Default `true`",
        "positive `state_bytes`",
        "`phases` | Default: every phase",
        "`observability` | Default policy",
        "`transition_declaration`",
        "`service_declaration`",
    ] {
        assert!(
            REFERENCE.contains(field),
            "reference must document canonical signal/binding field contract `{field}`"
        );
    }
}

#[test]
fn topology_guide_names_every_canonical_world_array() {
    for row in [
        "fault_domain",
        "network_interface",
        "network_segment",
        "network_medium",
        "network_forwarder",
        "network_queue",
        "network_path",
        "network_attachment",
        "network_contact_plan",
        "network_policy_artifact",
        "mobile_endpoint",
        "storage_device",
        "storage_controller",
        "storage_array",
        "storage_policy_artifact",
        "node_fault_capabilities",
    ] {
        assert!(
            TOPOLOGY_GUIDE.contains(&format!("`[[world.{row}]]`")),
            "topology guide must name canonical TOML row `[[world.{row}]]`"
        );
    }
    assert!(!REFERENCE.contains("world.fault_topology.storage_array"));
    assert!(REFERENCE.contains("`policy` reference"));
}

#[test]
fn security_relevant_daemon_options_are_in_the_reference() {
    for option in [
        "--daemon-ca",
        "--daemon-cert",
        "--daemon-key",
        "--production-qemu",
        "--qemu-rendezvous-icount",
        "--tls-cert",
        "--tls-key",
        "--client-ca",
        "--trusted-unauthenticated-bind",
        "--debug-role",
    ] {
        assert!(
            REFERENCE.contains(option),
            "reference must name daemon option `{option}`"
        );
    }
}

#[test]
fn effect_parameter_rows_reject_known_nonexistent_fields() {
    let custody_row = NETWORK_GUIDE
        .lines()
        .find(|line| line.starts_with("| `network.custody_queue` |"))
        .unwrap_or_else(|| panic!("custody queue contract row must exist"));
    assert!(!custody_row.contains("service policy"));
    assert!(!custody_row.contains("queue depth"));
}

#[test]
fn topology_policy_tables_retain_exact_high_risk_field_names() {
    for field in [
        "`responses = [{ response, headers }]`",
        "`source_ipv4?`",
        "`ipv4_identification`",
        "`completed_undelivered`",
        "`preserve_order_across_reconnect`",
        "`data_visibility_lag_nanos?`",
        "`path`, `version`, `mode`, `data`, `deleted`",
    ] {
        assert!(
            TOPOLOGY_GUIDE.contains(field),
            "topology policy reference must retain exact field contract `{field}`"
        );
    }
}

fn section(start: &str, end: &str) -> &'static str {
    REFERENCE
        .split_once(start)
        .map(|(_, tail)| tail)
        .and_then(|tail| tail.split_once(end))
        .map(|(section, _)| section)
        .unwrap_or_else(|| {
            panic!("reference section `{start}` through `{end}` must remain present")
        })
}

fn assert_exact_reference_rows<'a>(
    section: &str,
    expected: impl Iterator<Item = &'a str>,
    registry: &str,
) {
    let mut documented = BTreeMap::<&str, usize>::new();
    for line in section.lines().filter(|line| line.starts_with("| `")) {
        let Some(key) = line
            .strip_prefix("| `")
            .and_then(|line| line.split('`').next())
        else {
            panic!("{registry} reference row must begin with one code-formatted key: {line}");
        };
        if key == "kind" {
            continue;
        }
        *documented.entry(key).or_default() += 1;
    }
    let expected = expected.collect::<Vec<_>>();
    assert_eq!(
        documented.len(),
        expected.len(),
        "{registry} reference must contain no missing or extra rows"
    );
    for key in expected {
        assert_eq!(
            documented.get(key),
            Some(&1),
            "{registry} `{key}` must have exactly one reference row"
        );
    }
}

fn markdown_table_columns(line: &str) -> usize {
    let mut columns = 0_usize;
    let mut preceding_backslashes = 0_usize;
    for byte in line.bytes() {
        if byte == b'|' && preceding_backslashes.is_multiple_of(2) {
            columns += 1;
        }
        preceding_backslashes = if byte == b'\\' {
            preceding_backslashes + 1
        } else {
            0
        };
    }
    columns.saturating_sub(1)
}

fn assert_code_name(guide: &str, name: &str, vocabulary: &str) {
    assert!(
        guide.contains(&format!("`{name}`")),
        "task guide must name {vocabulary} `{name}`"
    );
}

fn debug_variant_as_snake_case(value: &impl std::fmt::Debug) -> String {
    let value = format!("{value:?}");
    let mut result = String::with_capacity(value.len());
    for (index, character) in value.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                result.push('_');
            }
            result.push(character.to_ascii_lowercase());
        } else {
            result.push(character);
        }
    }
    result
}
