//! Operation-local authentication with independently changing admission inputs.

use super::*;

#[tokio::test]
async fn authenticated_lease_reuses_signature_without_freezing_clock() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let floor = fresh_floor(&publication);
    let verifier = keys().1;
    let authenticated = verifier.authenticate_lease(&bytes).unwrap();
    let cohort = cohort(&publication);
    let profile = profile();
    let current = |clock| {
        authenticated.validate(
            &cohort,
            &profile,
            &floor,
            &floor.full_key,
            LeaseEffect::Put,
            clock,
        )
    };

    assert_eq!(current(clock(101)).unwrap().payload.not_after, integer(130));
    assert!(current(clock(127)).is_ok());
    assert!(current(clock(128)).is_err());
    assert!(current(clock(99)).is_err());
    assert!(current(LeaseClock {
        observed_at: 101,
        uncertainty: -1
    })
    .is_err());
    assert!(current(LeaseClock {
        observed_at: 101,
        uncertainty: 3
    })
    .is_err());
    assert!(current(clock(i64::MAX)).is_err());
}

#[tokio::test]
async fn authenticated_lease_rechecks_floor_scope_and_profile() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let floor = fresh_floor(&publication);
    let authenticated = keys().1.authenticate_lease(&bytes).unwrap();
    let cohort = cohort(&publication);
    let profile = profile();
    let initial = authenticated
        .validate(
            &cohort,
            &profile,
            &floor,
            &floor.full_key,
            LeaseEffect::Put,
            clock(101),
        )
        .unwrap();

    let mut denied = initial.next_floor.clone();
    denied.denied = true;
    let mut retired = initial.next_floor.clone();
    retired.retired = true;
    let mut forked = initial.next_floor.clone();
    forked.payload_digest = Some("f".repeat(64));
    let mut advanced_clock = initial.next_floor.clone();
    advanced_clock.clock_floor = integer(102);

    for changed in [&denied, &retired, &forked, &advanced_clock] {
        assert!(authenticated
            .validate(
                &cohort,
                &profile,
                changed,
                &floor.full_key,
                LeaseEffect::Put,
                clock(101),
            )
            .is_err());
    }

    let mut changed_profile = profile.clone();
    changed_profile.maximum_lifetime = integer(31);
    assert!(authenticated
        .validate(
            &cohort,
            &changed_profile,
            &floor,
            &floor.full_key,
            LeaseEffect::Put,
            clock(101),
        )
        .is_err());
    let mut changed_cohort = cohort.clone();
    changed_cohort.admission_digest = "e".repeat(64);
    assert!(authenticated
        .validate(
            &changed_cohort,
            &profile,
            &floor,
            &floor.full_key,
            LeaseEffect::Put,
            clock(101),
        )
        .is_err());
    assert!(authenticated
        .validate(
            &cohort,
            &profile,
            &floor,
            "managed/binding/objects/other",
            LeaseEffect::Put,
            clock(101),
        )
        .is_err());
    assert!(authenticated
        .validate(
            &cohort,
            &profile,
            &floor,
            &floor.full_key,
            LeaseEffect::ConditionalDelete,
            clock(101),
        )
        .is_err());

    assert!(authenticated
        .validate(
            &cohort,
            &profile,
            &initial.next_floor,
            &floor.full_key,
            LeaseEffect::Put,
            clock(102),
        )
        .is_ok());
}

#[tokio::test]
async fn authenticated_lease_refuses_changed_bytes_and_issuer() {
    let publication = publication();
    let bytes = issue(&publication, &RefCell::new(journal(&publication)), 100).await;
    let verifier = keys().1;

    // Preserve canonical field order so refusal exercises the signature check.
    let mut changed = bytes.clone();
    let signature = b"\"signature\":\"";
    let position = changed
        .windows(signature.len())
        .position(|part| part == signature)
        .unwrap()
        + signature.len();
    changed[position] = if changed[position] == b'0' {
        b'1'
    } else {
        b'0'
    };
    assert!(verifier.authenticate_lease(&changed).is_err());

    let other_public = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
    let other_verifier = EpochLeaseVerifier::from_bytes(KEY_ID.into(), &other_public).unwrap();
    assert!(other_verifier.authenticate_lease(&bytes).is_err());

    let mut noncanonical = bytes.clone();
    noncanonical.push(b' ');
    assert!(verifier.authenticate_lease(&noncanonical).is_err());
    assert!(verifier.authenticate_lease(&bytes).is_ok());
}
