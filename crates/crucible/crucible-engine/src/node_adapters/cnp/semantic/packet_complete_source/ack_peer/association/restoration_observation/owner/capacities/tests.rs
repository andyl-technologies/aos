//! Checks unreserved first-observation partials without creating native evidence.

use super::*;

fn partial() -> OriginalSourceRestorationObservationAttempt {
    let mut values = std::array::from_fn(|_| None);
    let mut text = String::with_capacity(193);
    text.push_str("failed first observation");
    let mut children = Vec::with_capacity(3);
    children.push(serde_json::Value::String(text));
    values[2] = Some(serde_json::Value::Array(children));
    OriginalSourceRestorationObservationAttempt {
        process: std::process::id(),
        thread: std::thread::current().id(),
        source: std::ptr::null(),
        controller: std::ptr::null(),
        binding: [7; 32],
        reserved: false,
        verified: false,
        banks: std::array::from_fn(|_| Vec::with_capacity(127)),
        values,
        record: None,
        underlying: None,
        scheduling: std::cell::OnceCell::new(),
    }
}

fn scheduling() -> NativeSchedulingObservation {
    NativeSchedulingObservation {
        node: Id::new("observation/data-node").unwrap(),
        owners: Vec::with_capacity(3),
        reached: crucible_node_format::Position::new(
            crucible_node_format::Tick::new(0),
            crucible_node_format::U64::new(0),
            crucible_node_format::Phase::BoundaryControl,
        ),
        closed_prefix: crucible_node_format::Position::new(
            crucible_node_format::Tick::new(0),
            crucible_node_format::U64::new(0),
            crucible_node_format::Phase::BoundaryControl,
        ),
        bounds: Vec::with_capacity(5),
        publications: Vec::with_capacity(7),
        input_progress: None,
        external_inputs: Vec::with_capacity(11),
        proof_ref: crucible_node_format::canonical::content_ref(
            b"scheduling DATA",
            "application/json",
        )
        .unwrap(),
    }
}

#[test]
fn observation_capacity_first_keeps_failed_banks_normalization_and_scheduling_spares() {
    let attempt = partial();
    attempt.scheduling.set(scheduling()).unwrap();
    let raw = attempt
        .allocated_bank_bytes_with_error::<RuntimeError>()
        .unwrap();
    let mut expected = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    expected.observe(attempt.scheduling.get().unwrap()).unwrap();
    let scheduling = expected.finish();
    let serde_json::Value::Array(array) = attempt.values[2].as_ref().unwrap() else {
        panic!("array fixture");
    };

    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    attempt.record_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 6 + scheduling.capacity_records);
    assert_eq!(
        facts.vector_capacity_bytes,
        raw + array.capacity() * size_of::<serde_json::Value>() + scheduling.vector_capacity_bytes
    );
    assert_eq!(
        facts.string_capacity_bytes,
        193 + scheduling.string_capacity_bytes
    );
    assert_eq!(facts.vector_banks, 5 + scheduling.vector_banks);
    assert!(attempt.authenticate_verified().is_err());
    assert!(attempt.source.is_null());
    assert!(attempt.controller.is_null());
    assert!(!attempt.reserved);
    assert!(!attempt.verified);
}

#[test]
fn observation_capacity_first_short_rows_keep_prior_component_and_raw_bank_prefix() {
    let attempt = partial();
    let prefix = String::with_capacity(211);
    let mut census = OriginalOwnerCapacityMetadataData::new(3, None);
    census.observe(&prefix).unwrap();

    assert_eq!(
        attempt.record_capacity_data(&mut census),
        Err(RuntimeError::ResourceLimit)
    );

    let facts = census.finish();
    assert_eq!(facts.capacity_records, 3);
    assert_eq!(facts.string_capacity_bytes, prefix.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        attempt.banks[..2].iter().map(Vec::capacity).sum::<usize>()
    );
    assert!(!attempt.reserved);
}

#[test]
fn observation_capacity_first_foreign_creator_precedes_rows() {
    for process in [true, false] {
        let mut attempt = partial();
        if process {
            attempt.process = attempt.process.wrapping_add(1);
        } else {
            attempt.thread = std::thread::spawn(|| std::thread::current().id())
                .join()
                .unwrap();
        }
        let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
        let expected = if process {
            RuntimeError::ForeignAuthority
        } else {
            RuntimeError::ThreadAffinity
        };

        assert_eq!(attempt.record_capacity_data(&mut census), Err(expected));

        assert_eq!(census.finish().capacity_records, 0);
    }
}
