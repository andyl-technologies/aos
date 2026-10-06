//! Actual independent entry/table loans and escaped subscriber lifetime checks.

use super::*;
use std::sync::atomic::Ordering;

fn source() -> Result<SchedulerEventLogEntry, EngineError> {
    crucible::test_support::condition_boundary_entry_for_test(
        0,
        VirtualTime { ticks: 1 },
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

#[test]
fn truncation_releases_bodies_and_retains_only_current_table_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let (budget, used) = session_streams::admission_tests::tracked_fixture_budget()?;
    let _scope = budget.enter();
    let baseline = used.load(Ordering::SeqCst);
    let child = budget.child()?;
    let account_bytes = used.load(Ordering::SeqCst) - baseline;
    drop(child);
    let source = source()?;
    let mut entries = AdmittedEventEntries::default();
    for _ in 0..32 {
        entries.append_copies(std::slice::from_ref(&source))?;
    }
    let full = used.load(Ordering::SeqCst);
    let table = (entries.entries.capacity() * std::mem::size_of::<SchedulerEventLogEntry>()
        + entries.credits.capacity() * std::mem::size_of::<DecodeCustody>()) as u64
        + 2 * account_bytes;
    assert!(full > baseline + table);
    entries.retain_before(0);
    assert_eq!(used.load(Ordering::SeqCst), baseline + table);
    entries.append_copies(std::slice::from_ref(&source))?;
    let pending = std::mem::take(&mut entries);
    assert_eq!(pending.len(), 1);
    drop(entries);
    assert!(used.load(Ordering::SeqCst) > baseline);
    drop(pending);
    assert_eq!(used.load(Ordering::SeqCst), baseline);
    Ok(())
}

#[test]
fn refused_append_preserves_the_existing_log_and_releases_staging()
-> Result<(), Box<dyn std::error::Error>> {
    let (budget, used) = session_streams::admission_tests::tracked_fixture_budget()?;
    let _scope = budget.enter();
    let source = source()?;
    let mut entries = AdmittedEventEntries::copied(std::slice::from_ref(&source))?;
    let before = used.load(Ordering::SeqCst);
    let held = budget.reserve_scratch_bytes(1024 * 1024 - before - 1)?;
    let saturated = used.load(Ordering::SeqCst);
    assert!(
        entries
            .append_copies(std::slice::from_ref(&source))
            .is_err()
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], source);
    assert_eq!(used.load(Ordering::SeqCst), saturated);
    drop(held);
    assert_eq!(used.load(Ordering::SeqCst), before);
    Ok(())
}

#[test]
fn final_subscriber_keeps_the_entry_credit_after_hub_truncation_and_drop()
-> Result<(), Box<dyn std::error::Error>> {
    let (budget, used) = session_streams::admission_tests::tracked_fixture_budget()?;
    let _scope = budget.enter();
    let baseline = used.load(Ordering::SeqCst);
    let source = source()?;
    let hub = SessionEventLog::new();
    hub.append_entries(std::slice::from_ref(&source))?;
    let mut stream = hub.subscribe(EventLogCursor::new(0));
    let frame = stream
        .try_recv()?
        .ok_or_else(|| std::io::Error::other("retained frame"))?;
    assert_eq!(&**frame.entry, &source);
    hub.truncate_to_len(0);
    drop(hub);
    drop(stream);
    let held = used.load(Ordering::SeqCst);
    assert!(held > baseline);
    let escaped = frame.entry.clone();
    drop(frame);
    assert_eq!(used.load(Ordering::SeqCst), held);
    assert_eq!(&**escaped, &source);
    drop(escaped);
    assert_eq!(used.load(Ordering::SeqCst), baseline);
    Ok(())
}
