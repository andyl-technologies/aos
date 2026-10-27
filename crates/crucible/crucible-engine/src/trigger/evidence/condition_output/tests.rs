//! Borrowed history equivalence and diagnostic allocation custody fixtures.

use super::*;
use std::error::Error;

fn timer_entry(
    sequence: u64,
    ticks: u64,
    action: Action,
) -> Result<SchedulerEventLogEntry, EngineError> {
    SchedulerEventLogEntry::with_payload_for_test(
        sequence,
        VirtualTime { ticks },
        SchedulerEventLogPayload::TriggerActionApplied(TriggerActionApplication {
            sequence,
            event: EventId::from_name("timer-history"),
            at: VirtualTime { ticks },
            path: Vec::new(),
            action,
        }),
    )
}

#[test]
fn borrowed_timer_history_matches_reconstructed_scoped_prefixes() -> Result<(), Box<dyn Error>> {
    let decoding = crate::test_support::fixture_decode_scope(8 * 1024 * 1024)?;
    let timer = TimerId {
        name: String::from("retry"),
    };
    let entries = vec![
        timer_entry(
            0,
            10,
            Action::ArmTimer {
                name: timer.clone(),
                after: SimDuration { ticks: 25 },
            },
        )?,
        timer_entry(
            1,
            20,
            Action::CancelTimer {
                name: timer.clone(),
            },
        )?,
        timer_entry(
            2,
            30,
            Action::ArmTimer {
                name: timer.clone(),
                after: SimDuration { ticks: 40 },
            },
        )?,
        timer_entry(
            3,
            40,
            Action::ArmTimer {
                name: timer.clone(),
                after: SimDuration { ticks: u64::MAX },
            },
        )?,
    ];
    let prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries(entries.clone())?;
    let policies = BTreeMap::new();
    for (index, expected) in [Some(35), None, Some(70), Some(70)].into_iter().enumerate() {
        let reconstructed =
            ConditionEventLogPrefix::from_scheduler_event_log_entries(entries[..=index].to_vec())?;
        let view = EvidencePrefix::at(&prefix, reconstructed.point());
        let evaluator = LoggedTruth {
            view: &view,
            policies: &policies,
            failure: std::cell::Cell::new(None),
        };

        assert_eq!(
            evaluator.timer_fire_time(&timer),
            reconstructed.timer_fires.get(&timer).copied(),
        );
        assert_eq!(
            evaluator.timer_fire_time(&timer),
            expected.map(|ticks| VirtualTime { ticks }),
        );
        assert!(std::ptr::eq(
            view.entries.as_ptr(),
            prefix.scheduler_entries.as_ptr()
        ));
    }
    decoding.check()?;
    Ok(())
}

#[test]
fn guest_reason_preserves_unicode_and_separator_bytes() -> Result<(), Box<dyn Error>> {
    let decoding = crate::test_support::fixture_decode_scope(4096)?;
    let details = vec![
        GuestAssertionDetail::new("clé", "λ=1"),
        GuestAssertionDetail::new("bytes", "a,b"),
    ];
    let reason = GuestReason {
        summary: format_args!("assertion {} failed", "α"),
        location: "guest.c:42",
        details: details_reason(&details),
    };

    assert_eq!(
        text(reason)?,
        "assertion α failed; location=guest.c:42; details=clé=λ=1,bytes=a,b",
    );
    assert_eq!(text(details_reason(&[]))?, "");
    decoding.check()?;
    Ok(())
}

#[test]
fn stamp_validation_borrows_success_and_retains_failed_diagnostic_credit()
-> Result<(), Box<dyn Error>> {
    let decoding = crate::test_support::fixture_decode_scope(1024 * 1024)?;
    let event = ObservableEvent::console_output(
        VirtualTime { ticks: 10 },
        NodeId {
            name: String::from("console-α"),
        },
        b"ready".to_vec(),
    );
    let entry = SchedulerEventLogEntry::with_payload_for_test(
        0,
        event.at(),
        SchedulerEventLogPayload::Observable(event.payload().clone()),
    )?;
    let kind = event.payload().black_box_observation_kind().unwrap();
    let before = decoding.retained_bytes();
    validate_observation_stamp(&entry, event.payload(), kind)?;
    assert_eq!(decoding.retained_bytes(), before);

    let mut time = entry.time().clone();
    time.stamp.node = Some(NodeId {
        name: String::from("wrong-β"),
    });
    let invalid = entry.with_time_for_test(time)?;
    let baseline = decoding.retained_bytes();
    let diagnostic = validate_observation_stamp(&invalid, event.payload(), kind).unwrap_err();
    assert!(matches!(
        diagnostic,
        ConditionEvaluationError::InvalidBlackBoxObservationStamp { .. }
    ));
    assert!(decoding.retained_bytes() > baseline);

    drop(diagnostic);
    assert_eq!(decoding.retained_bytes(), baseline);
    decoding.check()?;
    Ok(())
}
