//! Explicit edition-five launch pins reject partial or implicit enrollment.

// crucible-lint: allow panic-shortcut -- These native administration tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crate::args::PluginArgs;

fn fields() -> Vec<String> {
    vec![
        format!("node_initialization_commitment={}", "03".repeat(32)),
        format!("node_initialization_realize_digest={}", "04".repeat(32)),
        format!("node_initialization_policy_digest={}", "05".repeat(32)),
        "node_initialization_class_mask=7".into(),
        "node_initialization_max_callbacks=64".into(),
        format!("node_phase_commitment={}", "06".repeat(32)),
        format!("node_phase_policy_digest={}", "07".repeat(32)),
        "node_phase_mapping=1".into(),
        "node_phase_max_microsteps=1024".into(),
        format!("node_administration_commitment={}", "08".repeat(32)),
        format!("node_administration_policy_digest={}", "09".repeat(32)),
    ]
}

fn arguments(fields: &[String], edition: u32) -> String {
    format!(
        "simfd=3,slot=0,fault_node_hash={},process_generation=1,network_tx_next_seq=0,storage_completed_history_epochs=1048576,storage_completed_history_gaps=1048576,node_control_fd=9,node_control_scope_hash={},node_control_version={edition},{}",
        "01".repeat(32),
        "02".repeat(32),
        fields.join(",")
    )
}

#[test]
fn every_original_companion_pin_and_explicit_edition_are_required() {
    let complete = fields();
    let parsed = PluginArgs::parse(&arguments(&complete, 5)).unwrap();
    let native = parsed.native_node_control().unwrap();
    let role = native.administration().unwrap();
    assert_eq!(role.commitment, [8; 32]);
    assert_eq!(role.policy_digest, [9; 32]);
    assert!(native.initialization().is_some());
    assert!(native.phase().is_some());

    for missing in 0..complete.len() {
        let partial: Vec<_> = complete
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != missing)
            .map(|(_, field)| field.clone())
            .collect();
        assert!(PluginArgs::parse(&arguments(&partial, 5)).is_err());
    }
    for edition in 1..5 {
        assert!(PluginArgs::parse(&arguments(&complete, edition)).is_err());
    }
}

#[test]
fn zero_duplicate_and_partial_role_pins_never_upgrade_legacy_launch() {
    for index in [9, 10] {
        let mut zero = fields();
        let key = zero[index].split_once('=').unwrap().0.to_owned();
        zero[index] = format!("{key}={}", "00".repeat(32));
        assert!(PluginArgs::parse(&arguments(&zero, 5)).is_err());

        let mut duplicate = fields();
        duplicate.push(duplicate[index].clone());
        assert!(PluginArgs::parse(&arguments(&duplicate, 5)).is_err());
    }
}
