//! Privacy, bounded batch events and actual stream-counter lifecycle tests.

use super::*;

fn object() -> Object {
    Object {
        session: Session::new("private-session", "private-original"),
        client_operation_digest: digest("private-operation"),
        placement_digest: digest("private-placement"),
        operation_digest: Some(digest("private-effect")),
        complete_operation_digest: Some(digest("private-complete")),
        dependency_phase: DirectDependencyPhase::Visibility,
        byte_size: WireInteger::new(2 * 1024 * 1024 * 1024),
    }
}

#[test]
fn visibility_uses_metadata_and_untrusted_identifiers_never_cross_diagnostic_boundary() {
    let event = Event::new(
        Kind::QueueStart,
        Some(object()),
        "https://secret.invalid/?credential=canary",
    );
    let encoded = event.encoded().unwrap();
    assert_eq!(event.queue_class, Some(QueueClass::Metadata));
    for private in [
        "private-session",
        "private-original",
        "private-operation",
        "private-placement",
        "secret.invalid",
        "credential",
        "canary",
    ] {
        assert!(!encoded.contains(private));
    }
    let decoded: Event = serde_json::from_str(&encoded).unwrap();
    assert_eq!(
        decoded.object.unwrap().dependency_phase,
        DirectDependencyPhase::Visibility
    );
    assert_eq!(decoded.scope, Scope::ProductionQueue);
}

#[test]
fn complete_control_batch_is_bounded_and_preserves_all_original_correlations() {
    let mut event = Event::new(Kind::ControlRequest, None, "request");
    event.control = Some(Control {
        request_digest: digest("nonce"),
        public_body_digest: digest("public"),
        signed_body_digest: digest("signed"),
        reply_body_digest: None,
        step: Step::Promote,
        sessions: (0..64)
            .map(|index| Session::new(&index.to_string(), &format!("original-{index}")))
            .collect(),
    });
    assert!(event.encoded().unwrap().len() <= MAX_EVENT_BYTES);
    assert_eq!(event.control.as_ref().unwrap().sessions.len(), 64);
    event
        .control
        .as_mut()
        .unwrap()
        .sessions
        .resize(128, Session::new("extra", "original"));
    assert!(event.encoded().is_err());
}

#[test]
fn consumed_bytes_count_partial_failure_and_positive_reads_without_declared_size_substitution() {
    let _ = take_events();
    {
        let read = Read::new(object());
        read.consumed(64 * 1024);
        read.consumed(13);
    }
    let failed = take_events();
    assert_eq!(failed.len(), 2);
    assert_eq!(failed[0].kind, Kind::ProviderReadStart);
    assert_eq!(failed[1].kind, Kind::ProviderReadFinish);
    assert_eq!(failed[1].bytes, Some(WireInteger::new(64 * 1024 + 13)));
    assert_eq!(failed[1].outcome, Outcome::Unknown);
    assert_eq!(failed[0].attempt_digest, failed[1].attempt_digest);
    assert_eq!(failed[1].direction, Some(Direction::ProviderToWorker));
    assert_eq!(failed[1].scope, Scope::StorageRead);

    {
        let mut read = Read::new(object());
        read.consumed(19);
        read.positive();
    }
    let positive = take_events();
    assert_eq!(positive[1].bytes, Some(WireInteger::new(19)));
    assert_eq!(positive[1].outcome, Outcome::Positive);
}
