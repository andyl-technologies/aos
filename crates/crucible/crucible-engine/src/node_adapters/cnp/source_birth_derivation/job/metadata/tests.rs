//! Checks retained failure DATA without manufacturing a supervised Job.

use super::*;

#[test]
fn failed_outcome_preserves_spare_capacity_and_one_short_refuses() {
    let mut stdout = Vec::with_capacity(97);
    stdout.extend_from_slice(b"partial stdout");
    let stderr = Vec::with_capacity(53);
    let outcome = LinuxPureWorkerOutcome {
        child_id: None,
        memory_oom_kills: None,
        status: None,
        stdout,
        stderr,
        failure: None,
    };
    let pointers = (outcome.stdout.as_ptr(), outcome.stderr.as_ptr());
    let mut exact = OriginalOwnerCapacityMetadataData::new(2, None);

    record_failed_outcome(&outcome, &mut exact).unwrap();
    let facts = exact.finish();

    assert_eq!(facts.capacity_records, 2);
    assert_eq!(facts.vector_banks, 2);
    assert_eq!(facts.vector_capacity_bytes, 150);
    // Four inline fields, two vector fields and fourteen initialized bytes.
    assert_eq!(facts.observed_nodes, 20);
    let mut short = OriginalOwnerCapacityMetadataData::new(1, None);
    assert!(matches!(
        record_failed_outcome(&outcome, &mut short),
        Err(RuntimeError::ResourceLimit)
    ));
    assert_eq!(short.finish().capacity_records, 1);
    assert_eq!((outcome.stdout.as_ptr(), outcome.stderr.as_ptr()), pointers);
    assert_eq!(outcome.stdout, b"partial stdout");
    assert!(outcome.stderr.is_empty());
}

#[test]
fn original_failure_string_is_counted_without_rendering_or_replacing_it() {
    let mut message = String::with_capacity(137);
    message.push_str("private retained refusal");
    let pointer = message.as_ptr();
    let failure = SourceBirthJobFailure::Runtime(RuntimeError::SchedulerRefused(message));
    let mut census = OriginalOwnerCapacityMetadataData::new(1, None);

    record_failure(&failure, &mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.string_capacity_bytes, 137);
    assert_eq!(facts.capacity_records, 1);
    assert_eq!(facts.observed_nodes, 2);
    let mut short = OriginalOwnerCapacityMetadataData::new(0, None);
    assert!(matches!(
        record_failure(&failure, &mut short),
        Err(RuntimeError::ResourceLimit)
    ));
    let SourceBirthJobFailure::Runtime(RuntimeError::SchedulerRefused(message)) = &failure else {
        panic!("original refusal replaced");
    };
    assert_eq!(message.as_ptr(), pointer);
    assert_eq!(message, "private retained refusal");
}

#[test]
fn opaque_error_remains_original_and_creates_no_synthetic_capacity_row() {
    let original = std::io::Error::other(String::from("original private error"));
    let failure = SourceBirthJobFailure::Linux(LinuxPureWorkerError::Io(original));
    let mut census = OriginalOwnerCapacityMetadataData::new(0, None);

    record_failure(&failure, &mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 0);
    assert_eq!(facts.observed_nodes, 1);
    let SourceBirthJobFailure::Linux(LinuxPureWorkerError::Io(error)) = &failure else {
        panic!("original native error replaced");
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Other);
    assert_eq!(
        error.get_ref().unwrap().to_string(),
        "original private error"
    );
}
