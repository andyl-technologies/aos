//! Actual wall-clock issuance and immediate shared lease-consumer regressions.

use aos_hub_core::storage_authority::lease::{
    BoundedLeaseRevocationPolicy, EpochLeaseFloor, LeaseEffect,
};

use super::*;

fn actual_clock() -> LeaseClock {
    LeaseClock {
        observed_at: i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap(),
        uncertainty: 2,
    }
}

fn initialize_at(file: &Fixture, initial_clock: LeaseClock) -> AuthorityJournal {
    let mut current = publication();
    current.attestation.as_mut().unwrap().valid_until = initial_clock.observed_at + 600;
    AuthorityJournal::initialize_fresh(
        &file.path,
        &file.boundary,
        file.marker.clone(),
        current,
        BoundedLeaseRevocationPolicy {
            timing_profile: profile(),
        },
        initial_clock,
    )
    .unwrap()
}

#[tokio::test]
async fn real_native_issuance_is_immediately_valid_at_actual_consumer_time() {
    let file = Fixture::new();
    let journal = initialize_at(&file, actual_clock());
    let current = journal.load().unwrap();
    let native_clock = Arc::new(
        NativeClock::new(journal.clone(), 0, 1, current.journal.clock_floor.get()).unwrap(),
    );
    let server = test_server(
        &file,
        journal.clone(),
        native_clock,
        "127.0.0.1:0".parse().unwrap(),
    );
    let requested = actual_clock().observed_at;
    let request = IssuerRequest {
        protocol_version: 1,
        installation: file.marker.clone(),
        nonce: "a".repeat(64),
        issued_at: integer(requested),
        expires_at: integer(requested + 30),
        operation: IssuerOperation::Issue {
            cohort: cohort(&current.publication),
            requested_not_after: integer(requested + 30),
        },
    };

    // The production server performs actual SQLite commits and NativeClock
    // observations. The consumer samples UTC after the signed reply is ready;
    // no offset, wait or issuer-provided timestamp replaces its own clock.
    let bytes = server.execute(&request).await.unwrap();
    let reply = verify_issuer_reply_at_time(&server.inner.verifier, &request, &bytes, || {
        Ok(actual_clock())
    })
    .unwrap();
    let token = reply.lease.as_ref().unwrap().as_bytes();
    let consumer_clock = actual_clock();
    assert!(reply.current.journal.clock_floor.get() <= consumer_clock.observed_at);

    let full_key = "managed/binding/objects/blob";
    let floor = EpochLeaseFloor::initialize_fresh_guard(
        current.publication.authority.clone(),
        file.marker.executor_identity.clone(),
        full_key.into(),
        &profile(),
        consumer_clock,
    )
    .unwrap();
    let validated = server
        .inner
        .verifier
        .validate_lease(
            token,
            &cohort(&current.publication),
            &profile(),
            &floor,
            full_key,
            LeaseEffect::Put,
            consumer_clock,
        )
        .unwrap();
    let payload = &validated.payload;
    assert!(payload.issued_at.get() <= consumer_clock.observed_at);
    assert!(payload.not_after.get() <= requested + 30);
    assert_eq!(
        validated.next_floor.clock_floor.get(),
        consumer_clock.observed_at
    );

    // An uncertainty interval overlapping the issuer floor does not excuse a
    // consumer sample below that floor, or a rollback of its own retained floor.
    assert!(
        verify_issuer_reply_at_time(&server.inner.verifier, &request, &bytes, || Ok(
            LeaseClock {
                observed_at: reply.current.journal.clock_floor.get() - 1,
                uncertainty: 2,
            }
        ),)
        .is_err()
    );
    for invalid in [
        LeaseClock {
            observed_at: consumer_clock.observed_at - 1,
            uncertainty: 2,
        },
        LeaseClock {
            observed_at: consumer_clock.observed_at,
            uncertainty: 3,
        },
        LeaseClock {
            observed_at: consumer_clock.observed_at,
            uncertainty: -1,
        },
        LeaseClock {
            observed_at: payload.not_after.get() - 2,
            uncertainty: 2,
        },
    ] {
        assert!(server
            .inner
            .verifier
            .validate_lease(
                token,
                &cohort(&current.publication),
                &profile(),
                &validated.next_floor,
                full_key,
                LeaseEffect::Put,
                invalid,
            )
            .is_err());
    }

    let retained = journal.load().unwrap();
    let expiry = retained.journal.largest_issued_expiry;
    let cutoff = |observed_at| {
        retained.journal.policy.admission_cutoff(
            expiry,
            retained.journal.clock_floor,
            LeaseClock {
                observed_at,
                uncertainty: 2,
            },
        )
    };
    assert!(!cutoff(expiry.get() + 1).unwrap().reached);
    assert!(cutoff(expiry.get() + 2).unwrap().reached);
    assert!(cutoff(retained.journal.clock_floor.get() - 1).is_err());
    assert_eq!(retained.journal.last_sequence.get(), 1);
}

#[test]
fn existing_future_floor_and_excess_uncertainty_never_rewrite_clock_history() {
    let file = Fixture::new();
    let observed = actual_clock().observed_at;
    let future = observed + 60;
    let journal = initialize_at(
        &file,
        LeaseClock {
            observed_at: future,
            uncertainty: 2,
        },
    );
    let original = journal.load().unwrap();

    // Qualification fails before claiming a clock session. A later admissible
    // configuration still cannot lower an already retained journal floor.
    assert!(NativeClock::new(journal.clone(), 1, 1, future).is_err());
    let native = NativeClock::new(journal.clone(), 0, 1, future).unwrap();
    assert!(native.observe().is_err());
    assert!(native.observe().is_err());
    assert_eq!(journal.load().unwrap(), original);
    drop(native);
    assert!(NativeClock::new(file.reopen().unwrap(), 0, 1, future).is_err());
}
