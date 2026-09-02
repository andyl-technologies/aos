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

const USER_GUIDES: &[&str] = &[
    "authoring.md",
    "bindings.md",
    "ci.md",
    "coverage.md",
    "daemon.md",
    "debugging.md",
    "examples.md",
    "exploration.md",
    "fault-model-migration.md",
    "network-faults.md",
    "quickstart.md",
    "recorded-signals.md",
    "reference.md",
    "reproduction.md",
    "running.md",
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
