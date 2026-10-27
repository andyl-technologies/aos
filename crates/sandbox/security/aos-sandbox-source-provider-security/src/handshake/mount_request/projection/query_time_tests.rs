//! Pure authentication-time DATA regressions; no authority or guard fixtures.

use super::{query_authentication_time_v6, trusted_clock_evidence_digest, ObjectDigest};

#[test]
fn elapsed_wall_seconds_preserve_stored_authentication_evidence() {
    let stored_authenticated_at_seconds = 100;
    let boot_id = [1; 16];
    let session_binding = ObjectDigest::from_bytes([2; 32]);
    let trust_digest = ObjectDigest::from_bytes([3; 32]);
    let revocation_digest = ObjectDigest::from_bytes([4; 32]);
    let stored_evidence = trusted_clock_evidence_digest(
        boot_id,
        stored_authenticated_at_seconds,
        session_binding,
        trust_digest,
        revocation_digest,
    );

    for observed_now_seconds in [100, 101, 130] {
        let authentication_time = query_authentication_time_v6(
            stored_authenticated_at_seconds,
            observed_now_seconds,
        )
        .expect("the stored authentication time remains historical");
        let current_evidence = trusted_clock_evidence_digest(
            boot_id,
            authentication_time,
            session_binding,
            trust_digest,
            revocation_digest,
        );

        assert_eq!(authentication_time, stored_authenticated_at_seconds);
        assert_eq!(current_evidence, stored_evidence);
    }

    // A reminted current timestamp is precisely the old elapsed-second defect.
    assert_ne!(
        trusted_clock_evidence_digest(
            boot_id,
            101,
            session_binding,
            trust_digest,
            revocation_digest,
        ),
        stored_evidence,
    );
}

#[test]
fn future_or_negative_authentication_time_is_rejected() {
    for (stored, observed) in [(101, 100), (-1, 100), (0, -1)] {
        assert!(query_authentication_time_v6(stored, observed).is_err());
    }
}

#[test]
fn frozen_authentication_time_does_not_exempt_substituted_clock_scope() {
    let digest = |boot_id, session_binding, trust_digest, revocation_digest| {
        trusted_clock_evidence_digest(
            boot_id,
            100,
            ObjectDigest::from_bytes(session_binding),
            ObjectDigest::from_bytes(trust_digest),
            ObjectDigest::from_bytes(revocation_digest),
        )
    };
    let original = digest([1; 16], [2; 32], [3; 32], [4; 32]);

    for substituted in [
        digest([9; 16], [2; 32], [3; 32], [4; 32]),
        digest([1; 16], [9; 32], [3; 32], [4; 32]),
        digest([1; 16], [2; 32], [9; 32], [4; 32]),
        digest([1; 16], [2; 32], [3; 32], [9; 32]),
    ] {
        assert_ne!(substituted, original);
    }
}
