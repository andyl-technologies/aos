//! Negative coverage-attribution checks for the loaded-QEMU gate.

use super::*;

#[test]
fn guest_coverage_attribution_requires_a_whole_block_in_guest_text() {
    let observations = vec![
        crucible::ObservableEvent::coverage_block(
            Icount { retired: 12 },
            node_id(GATE_NODE),
            0xffff_0000,
            4,
        ),
        crucible::ObservableEvent::coverage_block(
            Icount { retired: 13 },
            node_id(GATE_NODE),
            GUEST_TEXT_END_EXCLUSIVE - 2,
            4,
        ),
        crucible::ObservableEvent::coverage_block(
            Icount { retired: 14 },
            node_id(GATE_NODE),
            GUEST_TEXT_START + 0x20,
            8,
        ),
    ];

    let entries = record_loaded_run_event_log("test", 32_768, observations)
        .unwrap_or_else(|error| panic!("test event log should append: {error}"));
    let coverage = event_log_coverage_projection(&entries);
    assert_eq!(guest_coverage_observation_count(&coverage, 32_768), 1);
}

#[test]
fn coverage_observations_change_feedback_but_not_canonical_causal_log() {
    let off = record_loaded_run_event_log("coverage-off", 32_768, Vec::new())
        .unwrap_or_else(|error| panic!("coverage-off event log should append: {error}"));
    let on = record_loaded_run_event_log(
        "coverage-on",
        32_768,
        vec![crucible::ObservableEvent::coverage_block(
            Icount { retired: 14 },
            node_id(GATE_NODE),
            GUEST_TEXT_START + 0x20,
            8,
        )],
    )
    .unwrap_or_else(|error| panic!("coverage-on event log should append: {error}"));

    let comparison = compare_event_log_determinism(&off, &on);
    assert!(comparison.passes());
    assert_eq!(comparison.expected().len(), 1);
    assert_eq!(comparison.reproduced().len(), 1);
    assert!(event_log_coverage_projection(&off).is_empty());
    assert_eq!(event_log_coverage_projection(&on).len(), 1);
}
