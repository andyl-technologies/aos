//! Original-authority lifetime and atomic suffix tests for owned prefixes.

use super::*;
use std::error::Error;

fn boundary(sequence: u64) -> Result<SchedulerEventLogEntry, EngineError> {
    SchedulerEventLogEntry::evaluation_boundary(
        sequence,
        VirtualTime {
            ticks: sequence + 1,
        },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

#[test]
fn prefix_copies_release_independently_and_preserve_named_maps() -> Result<(), Box<dyn Error>> {
    let fixture = crate::test_support::fixture_decode_scope(1 << 20)?;
    let mut prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries(vec![boundary(0)?])?;
    {
        let _scope = prefix.enter_original_decode();
        crate::owned_decode::charge_btree_entry::<EventId, VirtualTime>()?;
        prefix.event_firings.insert(
            copy(&EventId::from_name("event-with-owned-name"))?,
            VirtualTime { ticks: 1 },
        );
        crate::owned_decode::charge_btree_entry::<TimerId, VirtualTime>()?;
        prefix.timer_fires.insert(
            copy(&TimerId {
                name: "timer-with-owned-name".into(),
            })?,
            VirtualTime { ticks: 2 },
        );
    }
    let baseline = fixture.retained_bytes();

    for _ in 0..128 {
        let copied = prefix.try_clone_admitted()?;
        assert_eq!(copied, prefix);
        assert_eq!(copied.event_firings, prefix.event_firings);
        assert_eq!(copied.timer_fires, prefix.timer_fires);
        assert_eq!(copied.scheduler_entries, prefix.scheduler_entries);
        assert!(fixture.retained_bytes() > baseline);
        drop(copied);
        assert_eq!(fixture.retained_bytes(), baseline);
    }

    let first = prefix.try_clone_admitted()?;
    let one_copy = fixture.retained_bytes();
    let second = prefix.try_clone_admitted()?;
    assert!(fixture.retained_bytes() > one_copy);
    drop(second);
    assert_eq!(fixture.retained_bytes(), one_copy);
    drop(first);
    assert_eq!(fixture.retained_bytes(), baseline);
    fixture.check()?;
    Ok(())
}

#[test]
fn borrowed_suffix_is_copied_before_its_enclosing_owner_closes() -> Result<(), Box<dyn Error>> {
    let fixture = crate::test_support::fixture_decode_scope(1 << 20)?;
    let mut prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries(vec![boundary(0)?])?;
    let suffix = vec![boundary(1)?];
    prefix.append_scheduler_entries_ref(&suffix)?;
    drop(suffix);

    assert_eq!(prefix.scheduler_entries.len(), 2);
    assert_eq!(prefix.scheduler_entries[1].sequence(), 1);
    assert!(prefix.scheduler_entries[1].has_valid_content_hash()?);
    assert_eq!(prefix._append_custodies.len(), 2);
    let copied = prefix.try_clone_admitted()?;
    assert_eq!(copied.scheduler_entries, prefix.scheduler_entries);
    fixture.check()?;
    Ok(())
}

#[test]
fn refused_borrowed_suffix_preserves_prefix_and_refunds_staging() -> Result<(), Box<dyn Error>> {
    let fixture = crate::test_support::fixture_decode_scope(64 << 10)?;
    let mut prefix = ConditionEventLogPrefix::from_scheduler_event_log_entries(vec![boundary(0)?])?;
    let large_entry = {
        let _source_fixture = crate::test_support::fixture_decode_scope(4 << 20)?;
        SchedulerEventLogEntry::execution_budget_exhausted(
            1,
            VirtualTime { ticks: 2 },
            "large-source-field".repeat(8192),
        )?
    };
    let baseline = fixture.retained_bytes();
    let point = prefix.point;
    let offset = prefix.event_log_offset;
    let retained_batches = prefix._append_custodies.len();

    let result = prefix.append_scheduler_entries_ref(&[large_entry]);

    assert!(matches!(
        result,
        Err(ConditionEvaluationError::OriginalAdmission(_))
    ));
    assert_eq!(prefix.point, point);
    assert_eq!(prefix.event_log_offset, offset);
    assert_eq!(prefix.scheduler_entries.len(), 1);
    assert_eq!(prefix._append_custodies.len(), retained_batches);
    assert!(prefix.observable_events.is_empty());
    assert!(prefix.ordering_facts.is_empty());
    assert!(prefix.event_firings.is_empty());
    assert!(prefix.timer_fires.is_empty());
    assert_eq!(fixture.retained_bytes(), baseline);
    fixture.check()?;
    Ok(())
}
