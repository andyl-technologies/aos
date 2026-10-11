//! Counterexamples for inert ARM archive custody; no fixture grants authority.

// crucible-lint: allow rust-allow -- Invalid archive fixtures must fail assertions.
// crucible-lint: allow panic-shortcut -- Test fixture failures are intended assertion failures.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::{Phase, Position};
use serde_json::json;

fn boundary(tick: u64, ordinal: u64) -> Gem5Boundary {
    Gem5Boundary {
        tick: tick.into(),
        ordinal: ordinal.into(),
        tick_ordinal: u64::from(ordinal != 0).into(),
        logical_position: Position::new(
            tick.into(),
            u64::from(ordinal != 0).into(),
            Phase::BoundaryControl,
        ),
        has_next_event: true,
        next_tick: (tick + 1).into(),
        next_priority: 0,
        inventory: json!({"complete": false}),
    }
}

fn record() -> ArmRootArchiveImport {
    let before = boundary(0, 0);
    let after = boundary(10, 1);
    let original = crate::gem5::Gem5Run {
        kind: "run".to_owned(),
        operation: Id::new("original").unwrap(),
        exclusive_tick: 100.into(),
        maximum_events: 1.into(),
        exact_range: Some(crate::gem5::Gem5ExactRange {
            start: before.logical_position,
            limit: Position::new(100.into(), 0.into(), Phase::BoundaryControl),
            maximum_microsteps: 1_000_000.into(),
        }),
    };
    let prefix = crate::gem5::ArmRootPrefix {
        kind: "completed".to_owned(),
        operation: original.operation.clone(),
        original,
        before,
        after: after.clone(),
        processed_events: 1.into(),
        reason: "output".to_owned(),
        output: vec![91],
        publications: vec![crate::gem5::Gem5SerialPublication {
            facet: "serial".to_owned(),
            terminal: "system.terminal".to_owned(),
            output_id: 1.into(),
            tick: 10.into(),
            event_ordinal: 1.into(),
            tick_ordinal: 1.into(),
            causal_parent: 0.into(),
            payload: vec![91],
        }],
        exit_cause: None,
        exit_code: None,
    };
    let profile = canonical::content_ref(b"inert-test", "application/json").unwrap();
    ArmRootArchiveImport {
        capture: Id::new("capture").unwrap(),
        source: ArmRootHistoricalSource {
            schema: "crucible.gem5.arm-root-historical-source.v1".to_owned(),
            owner: Id::new("owner").unwrap(),
            incarnation: Id::new("incarnation").unwrap(),
            generation: 1.into(),
            profile,
            model_id: "arm-linux-vexpress-atomic-root-functional-v1".to_owned(),
            native_dialect: "crucible.gem5.arm-linux-native/1".to_owned(),
            bindings: BTreeMap::new(),
            resource_root: "/gone/resources".into(),
            image_root: "/gone/images".into(),
            temporary_root: "/gone/tmp".into(),
            timeout_nanoseconds: 1_000_000.into(),
        },
        source_supplementary_files_root: "/gone/images/ckpt_files".into(),
        boundary: after,
        original_outcomes: vec![
            canonical::canonical_json(&serde_json::to_value(prefix).unwrap()).unwrap(),
        ],
        pending: Some(Id::new("original").unwrap()),
        last_acknowledged: None,
        artifacts: Vec::new(),
        control_history: crate::gem5::ArmRootControlHistory::empty(),
    }
}

#[test]
fn typed_root_history_retains_serial_without_live_authority() {
    let input = record();
    let result = validate_outcomes(&input).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(
        result.values().next().unwrap().bytes(),
        input.original_outcomes[0]
    );
}

#[test]
fn changed_original_cut_or_custody_is_rejected() {
    for change in 0..6 {
        let mut input = record();
        match change {
            0 => input.boundary.ordinal = 2.into(),
            1 => input.pending = Some(Id::new("omitted").unwrap()),
            2 => input.last_acknowledged = input.pending.clone(),
            3 => input.last_acknowledged = Some(Id::new("omitted").unwrap()),
            4 => input
                .original_outcomes
                .push(input.original_outcomes[0].clone()),
            _ => input.original_outcomes.clear(),
        }
        assert!(validate_outcomes(&input).is_err(), "change {change}");
    }
}

#[test]
fn serial_model_and_actual_callback_permission_cannot_be_substituted() {
    for change in 0..6 {
        let mut input = record();
        let mut body: serde_json::Value =
            serde_json::from_slice(&input.original_outcomes[0]).unwrap();
        match change {
            0 => body["publications"][0]["guest_fd"] = json!(1),
            1 => body["publications"][0]["causal_parent"] = json!("17"),
            2 => body["publications"][0]["output_id"] = json!("2"),
            3 => body["original"]["maximum_events"] = json!("0"),
            4 => body["before"]["ordinal"] = json!("5"),
            _ => body["original"]["exact_range"]["maximum_microsteps"] = json!("99"),
        }
        input.original_outcomes[0] = canonical::canonical_json(&body).unwrap();
        assert!(validate_outcomes(&input).is_err(), "change {change}");
    }
}

fn wire_record() -> ArmRootArchiveImport {
    let mut input = record();
    input.control_history = crate::gem5::arm_root_history::fixture_for_archive_test();
    let prefix: crate::gem5::ArmRootPrefix =
        serde_json::from_slice(&input.original_outcomes[0]).unwrap();
    input
        .control_history
        .request(&serde_json::to_value(prefix.original).unwrap())
        .unwrap();
    input
        .control_history
        .push(
            crate::gem5::ArmRootControlKind::Response,
            input.original_outcomes[0].clone(),
        )
        .unwrap();
    input
}

#[test]
fn actual_control_packets_bind_original_held_custody() {
    let input = wire_record();
    let completed = validate_outcomes(&input).unwrap();
    validate_protocol_custody(&input, &completed).unwrap();
    for change in 0..4 {
        let mut changed = input.clone();
        match change {
            0 => changed.control_history.packets.pop().map(|_| ()).unwrap(),
            1 => {
                changed.control_history.packets[2].bytes =
                    canonical::canonical_json(&json!({"kind":"acknowledge","operation":"original"}))
                        .unwrap()
            }
            2 => changed.pending = None,
            _ => changed.original_outcomes[0].push(b' '),
        }
        assert!(
            validate_protocol_custody(&changed, &completed).is_err(),
            "change {change}"
        );
    }
}

#[test]
fn actual_admin_ack_bodies_cannot_be_inferred_from_identity() {
    let mut input = wire_record();
    input
        .control_history
        .request(&json!({"kind":"acknowledge","operation":"original"}))
        .unwrap();
    input
        .control_history
        .push(
            crate::gem5::ArmRootControlKind::Response,
            canonical::canonical_json(&json!({"kind":"acknowledged","operation":"original"}))
                .unwrap(),
        )
        .unwrap();
    input.pending = None;
    input.last_acknowledged = Some(Id::new("original").unwrap());
    let completed = validate_outcomes(&input).unwrap();
    validate_protocol_custody(&input, &completed).unwrap();
    for change in 0..4 {
        let mut changed = input.clone();
        match change {
            0 => {
                changed.control_history.packets.truncate(4);
            }
            1 => {
                changed.control_history.packets[4].bytes =
                    canonical::canonical_json(&json!({"kind":"ack_refused","operation":"original"}))
                        .unwrap()
            }
            2 => {
                changed.control_history.packets[5].bytes = canonical::canonical_json(
                    &json!({"kind":"acknowledged","operation":"different"}),
                )
                .unwrap()
            }
            _ => {
                changed.control_history.packets[5].bytes = canonical::canonical_json(
                    &json!({"kind":"acknowledged","operation":"original","extra":true}),
                )
                .unwrap()
            }
        }
        assert!(
            validate_protocol_custody(&changed, &completed).is_err(),
            "change {change}"
        );
    }
}

#[test]
fn installed_source_rejects_arbitrary_metadata_even_with_valid_syntax() {
    let input = record();
    assert!(input.source.installed_source().is_err());
}
