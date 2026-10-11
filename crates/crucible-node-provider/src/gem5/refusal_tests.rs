//! Adversarial pure native/3 refusal checks without a native authority claim.

// crucible-lint: allow rust-allow -- These native refusal fixtures must fail on invalid setup or an unmet assertion.
// crucible-lint: allow panic-shortcut -- Unwraps are confined to these single-shot model tests.
#![allow(clippy::unwrap_used)] // Malformed fixture or a failed test invariant must panic.

use super::super::Gem5ExactRange;
use super::*;
use crucible_node_contract::{Phase, Position};

fn position(tick: u64) -> Position {
    Position::new(tick.into(), 0.into(), Phase::BoundaryControl)
}

fn fixture() -> (
    Gem5DiagnosticCreditPolicy,
    Gem5Run,
    Gem5Boundary,
    Gem5RunRefusal,
) {
    let policy = Gem5DiagnosticCreditPolicy {
        schema: "crucible.gem5.diagnostic-credit-policy.v1".into(),
        maximum_object_bytes: 64.into(),
        maximum_total_bytes: 256.into(),
        maximum_files: 16.into(),
        refusal_schema: "crucible.gem5.run-refused.v1".into(),
    };
    let original = Gem5Run {
        kind: "run".into(),
        operation: Id::new("original/prefix-2").unwrap(),
        exclusive_tick: 100.into(),
        maximum_events: 1024.into(),
        exact_range: Some(Gem5ExactRange {
            start: position(37),
            limit: position(100),
            maximum_microsteps: 1024.into(),
        }),
    };
    let before = Gem5Boundary {
        tick: 37.into(),
        logical_position: position(37),
        ordinal: 19.into(),
        tick_ordinal: 2.into(),
        has_next_event: true,
        next_tick: 38.into(),
        next_priority: 0,
        inventory: serde_json::json!({"schema":"model-test-only","complete":false}),
    };
    let refused = Gem5RunRefusal {
        kind: "run_refused".into(),
        schema: policy.refusal_schema.clone(),
        operation: original.operation.clone(),
        original: original.clone(),
        boundary: before.clone(),
        processed_events: 0.into(),
        reason: "diagnostic_credit".into(),
        credit: Gem5RefusalCredit {
            required_files: 1.into(),
            available_files: 5.into(),
            required_bytes: 64.into(),
            available_bytes: 63.into(),
            reserved_files: 0.into(),
            reserved_bytes: 0.into(),
        },
    };
    (policy, original, before, refused)
}

fn bytes(value: &impl Serialize) -> Vec<u8> {
    canonical::canonical_json(&serde_json::to_value(value).unwrap()).unwrap()
}

#[test]
fn refused_subordinate_poll_preserves_earlier_grant_progress_and_raw_receipt() {
    let (policy, original, before, refusal) = fixture();
    let raw = bytes(&refusal);
    let parsed =
        parse_run_refusal(&raw, GEM5_RESERVATION_PROTOCOL, &policy, &original, &before).unwrap();

    assert_eq!(parsed.bytes(), raw);
    assert_eq!(parsed.receipt().processed_events.get(), 0);
    assert_eq!(parsed.receipt().boundary.ordinal.get(), 19);
    assert_eq!(parsed.receipt().boundary.logical_position, position(37));
    assert_eq!(parsed.receipt().original.operation, original.operation);
}

#[test]
fn legacy_dialect_and_missing_or_integer_credit_fields_never_fallback() {
    let (policy, original, before, refusal) = fixture();
    assert!(
        parse_run_refusal(
            &bytes(&refusal),
            "crucible.gem5.native/2",
            &policy,
            &original,
            &before
        )
        .is_err()
    );
    for mutation in ["missing", "integer", "leading_zero", "unknown"] {
        let mut value = serde_json::to_value(&refusal).unwrap();
        match mutation {
            "missing" => {
                value["credit"]
                    .as_object_mut()
                    .unwrap()
                    .remove("reserved_bytes");
            }
            "integer" => value["processed_events"] = serde_json::json!(0),
            "leading_zero" => value["credit"]["available_bytes"] = serde_json::json!("063"),
            "unknown" => value["output"] = serde_json::json!([]),
            _ => unreachable!(),
        }
        assert!(
            parse_run_refusal(
                &bytes(&value),
                GEM5_RESERVATION_PROTOCOL,
                &policy,
                &original,
                &before
            )
            .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn changed_original_range_boundary_inventory_and_nonzero_callbacks_refuse() {
    let (policy, original, before, refusal) = fixture();
    for mutation in ["range", "boundary", "inventory", "progress"] {
        let mut changed = refusal.clone();
        match mutation {
            "range" => {
                changed
                    .original
                    .exact_range
                    .as_mut()
                    .unwrap()
                    .limit
                    .microstep = 1.into()
            }
            "boundary" => changed.boundary.ordinal = 20.into(),
            "inventory" => changed.boundary.inventory["complete"] = serde_json::json!(true),
            "progress" => changed.processed_events = 1.into(),
            _ => unreachable!(),
        }
        assert!(
            parse_run_refusal(
                &bytes(&changed),
                GEM5_RESERVATION_PROTOCOL,
                &policy,
                &original,
                &before
            )
            .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn false_credit_shortage_and_nonzero_acquired_reservation_refuse() {
    let (policy, original, before, refusal) = fixture();
    for mutation in ["sufficient", "reserved", "wrong_requirement", "oversized"] {
        let mut changed = refusal.clone();
        match mutation {
            "sufficient" => changed.credit.available_bytes = 64.into(),
            "reserved" => changed.credit.reserved_files = 1.into(),
            "wrong_requirement" => changed.credit.required_bytes = 63.into(),
            "oversized" => changed.credit.available_files = 17.into(),
            _ => unreachable!(),
        }
        assert!(
            parse_run_refusal(
                &bytes(&changed),
                GEM5_RESERVATION_PROTOCOL,
                &policy,
                &original,
                &before
            )
            .is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn publication_ack_cannot_settle_an_original_refusal() {
    let (policy, original, before, refusal) = fixture();
    let parsed = parse_run_refusal(
        &bytes(&refusal),
        GEM5_RESERVATION_PROTOCOL,
        &policy,
        &original,
        &before,
    )
    .unwrap();
    let accepted = Gem5RefusalAcknowledgement {
        kind: "refusal_acknowledged".into(),
        operation: original.operation.clone(),
    };
    assert_eq!(
        validate_refusal_acknowledgement(&bytes(&accepted), &parsed).unwrap(),
        accepted
    );
    for mutation in ["kind", "identity", "extra"] {
        let mut value = serde_json::to_value(&accepted).unwrap();
        match mutation {
            "kind" => value["kind"] = serde_json::json!("acknowledged"),
            "identity" => value["operation"] = serde_json::json!("another/prefix"),
            "extra" => value["outputs"] = serde_json::json!([]),
            _ => unreachable!(),
        }
        assert!(
            validate_refusal_acknowledgement(&bytes(&value), &parsed).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn noncanonical_or_oversized_receipts_refuse_before_retention() {
    let (policy, original, before, refusal) = fixture();
    let mut raw = bytes(&refusal);
    raw.push(b' ');
    assert!(
        parse_run_refusal(&raw, GEM5_RESERVATION_PROTOCOL, &policy, &original, &before).is_err()
    );
    let oversized = vec![b' '; GEM5_NATIVE_FRAME_BYTES + 1];
    assert!(
        parse_run_refusal(
            &oversized,
            GEM5_RESERVATION_PROTOCOL,
            &policy,
            &original,
            &before
        )
        .is_err()
    );
}

#[test]
fn arm_explicit_installed_dialect_accepts_original_refusal_without_retagging() {
    let (policy, original, before, refusal) = fixture();
    let raw = bytes(&refusal);
    let parsed = parse_run_refusal_for_model(
        &raw,
        "crucible.gem5.arm-linux-native/1",
        super::super::model::Gem5ModelDialect::ArmLinux,
        &policy,
        &original,
        &before,
    )
    .unwrap();
    assert_eq!(parsed.bytes(), raw);
    assert_eq!(parsed.receipt().boundary.ordinal.get(), 19);
    assert_eq!(parsed.receipt().original, original);
}

#[test]
fn arm_refusal_cannot_negotiate_se_or_legacy_dialect() {
    let (policy, original, before, refusal) = fixture();
    for (wire, selected) in [
        (
            "crucible.gem5.native/3",
            super::super::model::Gem5ModelDialect::ArmLinux,
        ),
        (
            "crucible.gem5.arm-linux-native/1",
            super::super::model::Gem5ModelDialect::ReservedSe,
        ),
        (
            "crucible.gem5.native/2",
            super::super::model::Gem5ModelDialect::LegacySe,
        ),
    ] {
        assert!(
            parse_run_refusal_for_model(
                &bytes(&refusal),
                wire,
                selected,
                &policy,
                &original,
                &before
            )
            .is_err()
        );
    }
}
