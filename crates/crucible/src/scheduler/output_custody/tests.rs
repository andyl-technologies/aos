//! Lifetime regressions for retained scheduler output loans.

use super::*;

#[test]
fn independent_output_copies_release_their_arrays_on_drop() -> Result<(), Box<dyn std::error::Error>>
{
    let origin = crate::test_support::fixture_decode_scope(128 * 1024)?;
    let initial = origin.retained_bytes();
    let input = crate::owned_decode::require_current_custody()?;
    let bank = crate::owned_decode::require_current_child_budget()?;
    let append = {
        let _scope = bank.enter();
        crate::owned_decode::charge_array::<u8>(4096)?;
        SchedulerEventLogAppend {
            entries: Vec::new(),
            segment_bytes: vec![7; 4096],
            segment_text: String::new(),
            segment_hash: None,
            offset: EventLogOffset::default(),
            event_log_custody: EventLogOutputCustody::from_budget(&bank, input)?,
        }
    };
    drop(bank);
    let held = origin.retained_bytes();
    assert!(held > initial + 4096);

    let copy = append.try_clone_admitted()?;
    let two_copies = origin.retained_bytes();
    assert!(two_copies >= held + 4096);
    assert_eq!(copy.segment_bytes, append.segment_bytes);
    drop(copy);
    assert_eq!(origin.retained_bytes(), held);

    for _ in 0..1000 {
        let copy = append.try_clone_admitted()?;
        assert_eq!(copy.segment_bytes, append.segment_bytes);
        drop(copy);
        assert_eq!(origin.retained_bytes(), held);
    }
    drop(append);
    assert_eq!(origin.retained_bytes(), initial);
    origin.check()?;
    Ok(())
}

#[test]
fn output_growth_keeps_only_the_current_entry_table_loan() -> Result<(), Box<dyn std::error::Error>>
{
    let origin = crate::test_support::fixture_decode_scope(128 * 1024)?;
    let mut custody = EventLogOutputCustody::retain_current()?;
    let mut values = Vec::<u64>::new();
    let before = origin.retained_bytes();
    custody.reserve_entries(&mut values, 1)?;
    values.push(1);
    let overhead =
        origin.retained_bytes() - before - (values.capacity() * std::mem::size_of::<u64>()) as u64;

    for value in 1..4096 {
        custody.reserve_entries(&mut values, 1)?;
        values.push(value);
    }
    assert_eq!(
        origin.retained_bytes(),
        before + overhead + (values.capacity() * std::mem::size_of::<u64>()) as u64
    );
    drop(values);
    drop(custody);
    origin.check()?;
    Ok(())
}
