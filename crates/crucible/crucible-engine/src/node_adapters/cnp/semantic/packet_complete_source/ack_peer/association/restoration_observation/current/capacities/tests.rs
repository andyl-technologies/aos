//! Checks actual history spare slots without manufacturing a quoted attempt.
//!
//! A populated current attempt requires its independently issued construction
//! row. These controls keep only real uninitialized Vec capacity as DATA.

use super::*;

#[test]
fn observation_capacity_current_keeps_failed_history_spare_attempt_geometry() {
    let mut history = CurrentObservationHistory::new();
    history.attempts = Vec::with_capacity(3);
    history.failed = true;
    let backing = history.attempts.as_ptr();
    let bytes = history.attempts.capacity() * size_of::<CurrentObservationAttempt>();
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    history.record_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.vector_banks, 1);
    assert_eq!(facts.vector_capacity_bytes, bytes);
    assert_eq!(history.attempts.as_ptr(), backing);
    assert!(history.attempts.is_empty());
    assert!(history.failed);
    assert!(history.poison_next_data(1).is_err());
    assert!(CurrentObservationHistory::capacity_counter_scratch_data() > 0);
}

#[test]
fn observation_capacity_current_short_rows_keep_prior_component() {
    let mut history = CurrentObservationHistory::new();
    history.attempts = Vec::with_capacity(3);
    let prefix = String::with_capacity(223);
    let mut census = OriginalOwnerCapacityMetadataData::new(1, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        history.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.vector_banks, 0);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert!(history.attempts.is_empty());
    assert!(!history.failed);
}

#[test]
fn observation_capacity_current_foreign_creator_precedes_rows() {
    for process in [true, false] {
        let mut history = CurrentObservationHistory::new();
        if process {
            history.process = history.process.wrapping_add(1);
        } else {
            history.thread = std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
        }
        let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
        let expected = if process {
            RuntimeError::ForeignAuthority
        } else {
            RuntimeError::ThreadAffinity
        };

        assert_eq!(history.record_capacity_data(&mut census), Err(expected));

        assert_eq!(census.finish().capacity_records, 0);
    }
}
