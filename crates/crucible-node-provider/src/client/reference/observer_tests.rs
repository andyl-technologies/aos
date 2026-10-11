//! Component checks for independently reserved inert observation custody.

// crucible-lint: allow rust-allow -- malformed and partial observation assertions deliberately panic.
// crucible-lint: allow panic-shortcut -- These observer tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::canonical;

use super::*;

fn recorder() -> (ObservationRecorder, ObservationHandle) {
    ObservationRecorder::reserve(super::super::tests::scope(), super::super::tests::limits())
        .unwrap()
}

#[test]
fn handle_is_thread_safe_data_and_survives_recorder_retirement() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ObservationHandle>();
    let (recorder, handle) = recorder();
    let payload = b"original nonsecret output";
    let reference = canonical::content_ref(payload, "application/octet-stream").unwrap();
    {
        let mut archive = recorder.archive.lock().unwrap();
        let object = archive.append(&reference, payload).unwrap();
        archive.objects.push(object);
    }
    drop(recorder);

    let references = handle.content_references().unwrap();
    let result = std::thread::spawn(move || {
        handle
            .snapshot(&[], &references, super::super::tests::limits())
            .unwrap()
    })
    .join()
    .unwrap();
    assert!(result.recording_complete);
    assert!(!result.observed_unknown);
    assert_eq!(result.evidence.objects[0].bytes.as_slice(), payload);
    assert_eq!(result.evidence.objects[0].reference, reference);
}

#[test]
fn actual_arena_capacity_is_reserved_before_any_bytes_are_admitted() {
    let (recorder, _) = recorder();
    let archive = recorder.archive.lock().unwrap();
    assert!(archive.bytes.capacity() >= archive.limits.maximum_bytes);
    assert!(archive.requests.capacity() >= archive.limits.maximum_requests);
    assert!(archive.objects.capacity() >= archive.limits.maximum_objects);
    assert!(archive.bytes.is_empty());
    assert!(archive.requests.is_empty());
    assert!(archive.objects.is_empty());
}

#[test]
fn arena_overflow_never_discards_original_bytes_or_promotes_completeness() {
    let (recorder, handle) = recorder();
    let payload = b"original";
    let reference = canonical::content_ref(payload, "application/octet-stream").unwrap();
    {
        let mut archive = recorder.archive.lock().unwrap();
        let object = archive.append(&reference, payload).unwrap();
        archive.objects.push(object);
        let original_bytes = archive.bytes.clone();
        archive.limits.maximum_bytes = payload.len();
        assert!(archive.append(&reference, payload).is_err());
        assert_eq!(archive.bytes, original_bytes);
        archive.failure = Some("component observation capacity exhausted");
    }

    let recorded = handle
        .snapshot(&[], &[reference], super::super::tests::limits())
        .unwrap();
    assert!(!recorded.recording_complete);
    assert_eq!(recorded.evidence.objects[0].bytes.as_slice(), payload);
    assert_eq!(
        recorded.recording_failure.0,
        Some("component observation capacity exhausted")
    );
    assert!(recorded.encode(1).is_err());
    assert!(recorded.encode(65536).is_ok());
}

#[test]
fn dropped_attempt_marks_unknown_without_granting_or_releasing_native_authority() {
    let (recorder, handle) = recorder();
    drop(recorder.attempt());
    let observed = handle
        .snapshot(&[], &[], super::super::tests::limits())
        .unwrap();
    assert!(!observed.recording_complete);
    assert!(observed.observed_unknown);
    assert_eq!(
        observed.recording_failure.0,
        Some("original control observation unwound")
    );

    recorder.attempt().finish();
    let after = handle
        .snapshot(&[], &[], super::super::tests::limits())
        .unwrap();
    assert!(!after.recording_complete);
    assert_eq!(after.recording_failure, observed.recording_failure);
}

#[test]
fn unavailable_and_duplicate_selectors_cannot_fabricate_receipt_objects() {
    let (recorder, handle) = recorder();
    let payload = b"original";
    let reference = canonical::content_ref(payload, "application/octet-stream").unwrap();
    let unavailable = canonical::content_ref(b"missing", "application/octet-stream").unwrap();
    {
        let mut archive = recorder.archive.lock().unwrap();
        let object = archive.append(&reference, payload).unwrap();
        archive.objects.push(object);
    }
    assert!(
        handle
            .snapshot(&[], &[unavailable], super::super::tests::limits())
            .is_err()
    );
    assert!(
        handle
            .snapshot(
                &[],
                &[reference.clone(), reference],
                super::super::tests::limits(),
            )
            .is_err()
    );
    assert!(handle.request_keys().unwrap().is_empty());
}
