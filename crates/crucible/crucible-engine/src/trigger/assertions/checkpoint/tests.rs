//! Canonical continuation, parser refusal, and returned-byte custody regressions.

use super::*;
use crate::test_support::fixture_decode_scope;

#[test]
fn cbor_roundtrip_preserves_large_scalar_and_encoded_credit_outlives_checkpoint()
-> Result<(), Box<dyn Error>> {
    let scope = fixture_decode_scope(8 << 20)?;
    let marker = GuestAssertionMarker::new(
        AssertionId::from_name("large-cbor"),
        "m".repeat(9000),
        GuestAssertionKind::Always,
        true,
        true,
        Vec::new(),
        "guest",
    );
    let evaluator = HostAssertionEvaluator::new(&Properties::empty())?
        .with_guest_assertion_catalog(&[marker])?;
    let baseline = scope.retained_bytes();
    let checkpoint = evaluator.checkpoint()?;
    let bytes = checkpoint.canonical_bytes()?;
    let decoded = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
    assert_eq!(decoded.wire.guest_marker_states[0].message.len(), 9000);
    assert_eq!(decoded.canonical_bytes()?.as_slice(), bytes.as_slice());
    drop(decoded);
    drop(checkpoint);
    assert!(scope.retained_bytes() > baseline);
    assert!(bytes.starts_with(MAGIC));
    drop(bytes);
    assert_eq!(scope.retained_bytes(), baseline);
    Ok(())
}

#[test]
fn parser_admission_refuses_before_decode_and_retains_typed_error_credit()
-> Result<(), Box<dyn Error>> {
    let mut payload = Vec::from(MAGIC);
    payload.push(0xa0); // A valid CBOR map, but no required continuation fields.
    let scope = fixture_decode_scope(4096)?;
    let baseline = scope.retained_bytes();
    let error = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&payload)
        .err()
        .ok_or_else(|| io::Error::other("fixture must refuse parser admission"))?;
    assert!(matches!(
        error,
        HostAssertionCheckpointError::Admission { .. }
    ));
    assert!(error.source().is_some());
    assert!(scope.retained_bytes() > baseline);
    drop(error);
    assert_eq!(scope.retained_bytes(), baseline);
    Ok(())
}

#[test]
fn truncated_huge_declared_scalar_does_not_allocate_declared_extent() -> Result<(), Box<dyn Error>>
{
    let scope = fixture_decode_scope(1 << 20)?;
    let baseline = scope.retained_bytes();
    let mut payload = Vec::from(MAGIC);
    // A definite text string declaring u64::MAX bytes, with no body.
    payload.push(0x7b);
    payload.extend_from_slice(&u64::MAX.to_be_bytes());
    assert!(matches!(
        HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&payload),
        Err(HostAssertionCheckpointError::Malformed)
    ));
    assert_eq!(scope.retained_bytes(), baseline);
    scope.check()?;
    Ok(())
}

#[test]
fn canonical_empty_wire_remains_the_same_cbor_envelope() -> Result<(), Box<dyn Error>> {
    let _scope = fixture_decode_scope(1 << 20)?;
    let evaluator = HostAssertionEvaluator::new(&Properties::empty())?;
    let checkpoint = evaluator.checkpoint()?;
    let actual = checkpoint.canonical_bytes()?;
    let mut oracle = Vec::from(MAGIC);
    ciborium::ser::into_writer(&checkpoint.wire, &mut oracle)?;
    assert_eq!(actual.as_slice(), oracle.as_slice());
    let mut trailing = oracle;
    trailing.push(0);
    assert!(matches!(
        HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&trailing),
        Err(HostAssertionCheckpointError::Noncanonical)
    ));
    Ok(())
}

#[test]
fn long_unknown_identifier_and_extreme_numeric_errors_release_parser_bank()
-> Result<(), Box<dyn Error>> {
    let scope = fixture_decode_scope(2 << 20)?;
    let baseline = scope.retained_bytes();
    for payload in [
        ciborium::value::Value::Map(vec![(
            ciborium::value::Value::Text("unknown\nfield\0".repeat(512)),
            ciborium::value::Value::Null,
        )]),
        ciborium::value::Value::Float(f64::MAX),
        ciborium::value::Value::Float(f64::from_bits(1)),
    ] {
        let mut bytes = Vec::from(MAGIC);
        ciborium::ser::into_writer(&payload, &mut bytes)?;
        assert!(matches!(
            HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes),
            Err(HostAssertionCheckpointError::Malformed)
        ));
        assert_eq!(scope.retained_bytes(), baseline);
    }
    scope.check()?;
    Ok(())
}

#[test]
fn borrowed_assertion_comparison_preserves_all_wire_continuations() -> Result<(), Box<dyn Error>> {
    let _original = fixture_decode_scope(16 << 20)?;
    let marker = GuestAssertionMarker::new(
        AssertionId::from_name("comparison-marker"),
        "original message",
        GuestAssertionKind::Always,
        true,
        true,
        Vec::new(),
        "original location",
    );
    let evaluator = HostAssertionEvaluator::new(&Properties::empty())?
        .with_guest_assertion_catalog(&[marker])?;
    let mut captured = evaluator.checkpoint()?;
    captured.wire.states.push(HostAssertionStateWire {
        assertion: AssertionId::from_name("comparison-property"),
        lifecycle: PropertyLifecycleState::Declared,
        terminal: None,
        evaluated: false,
        eventually_triggered: false,
        eventually_satisfied_at: None,
        pending_eventually: Vec::new(),
        proximity: None,
    });
    let bytes = captured.canonical_bytes()?;
    let baseline = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
    let identical = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
    assert!(baseline.same_continuation(&identical));
    drop(identical);

    type Mutation = fn(&mut HostAssertionEvaluatorWire);
    let mutations: &[(&str, Mutation)] = &[
        ("property identity", |wire| {
            wire.states[0].assertion = AssertionId::from_name("another-property");
        }),
        ("property lifecycle", |wire| {
            wire.states[0].lifecycle = PropertyLifecycleState::Passing;
        }),
        ("property terminal", |wire| {
            wire.states[0].terminal = Some(comparison_terminal());
        }),
        ("evaluation latch", |wire| wire.states[0].evaluated = true),
        ("eventually trigger", |wire| {
            wire.states[0].eventually_triggered = true
        }),
        ("eventually satisfaction", |wire| {
            wire.states[0].eventually_satisfied_at = Some(VirtualTime { ticks: 1 });
        }),
        ("eventually obligations", |wire| {
            wire.states[0]
                .pending_eventually
                .push(EventuallyObligation {
                    triggered_at: VirtualTime { ticks: 1 },
                    deadline: VirtualTime { ticks: 2 },
                });
        }),
        ("proximity minimum", |wire| {
            wire.states[0].proximity = Some(HostAssertionProximityMinimum {
                distance: u128::MAX,
                at: VirtualTime { ticks: 1 },
                event_log_offset: EventLogOffset::new(ContentHash::default(), 2, 3),
            });
        }),
        ("marker identity", |wire| {
            wire.guest_marker_states[0].id = AssertionId::from_name("another-marker");
        }),
        ("marker lifecycle", |wire| {
            wire.guest_marker_states[0].lifecycle = PropertyLifecycleState::Passing;
        }),
        ("marker message", |wire| {
            wire.guest_marker_states[0].message.push('!')
        }),
        ("marker kind", |wire| {
            wire.guest_marker_states[0].kind = GuestAssertionKind::Sometimes;
        }),
        ("marker must hit", |wire| {
            wire.guest_marker_states[0].must_hit = false
        }),
        ("marker details", |wire| {
            wire.guest_marker_states[0]
                .details
                .push(GuestAssertionDetail {
                    key: String::from("extra"),
                    value: String::from("detail"),
                });
        }),
        ("marker location", |wire| {
            wire.guest_marker_states[0].location.push('!')
        }),
        ("marker observation", |wire| {
            wire.guest_marker_states[0].observed_true = true
        }),
        ("marker counter", |wire| {
            wire.guest_marker_states[0].last_icount = Some(Icount { retired: 1 });
        }),
        ("marker node", |wire| {
            wire.guest_marker_states[0].last_node = Some(NodeId {
                name: String::from("node"),
            });
        }),
        ("marker terminal", |wire| {
            wire.guest_marker_states[0].terminal = Some(comparison_terminal());
        }),
        ("marker declaration", |wire| {
            wire.guest_marker_states[0].declared_message = Some(String::from("changed"));
        }),
        ("once latches", |wire| wire.once_latches.push(vec![1])),
        ("quiescence", |wire| {
            wire.terminal_quiescence = Some(SchedulerQuiescence {
                blockers: Vec::new(),
            });
        }),
        ("event log prefix", |wire| {
            wire.last_prefix = Some(EventLogOffset::new(ContentHash::default(), 1, 2));
        }),
    ];

    // Each negative changes one field after canonical decoding. The unchanged
    // identities deliberately cannot hide altered mutable continuation values.
    for (role, mutate) in mutations {
        let mut candidate = HostAssertionEvaluatorCheckpoint::from_canonical_bytes(&bytes)?;
        mutate(&mut candidate.wire);
        assert!(!baseline.same_continuation(&candidate), "omitted {role}");
    }
    Ok(())
}

fn comparison_terminal() -> HostAssertionTerminal {
    HostAssertionTerminal {
        kind: HostAssertionOutcomeKind::Warning,
        lifecycle: PropertyLifecycleState::Passing,
        at: VirtualTime { ticks: 1 },
        reason: String::from("different terminal state"),
        evidence: None,
    }
}
