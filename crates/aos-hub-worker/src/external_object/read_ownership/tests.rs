//! Signed read-window, current ownership and real shared-pool regressions.

use std::{cell::RefCell, future::Future as _, task::Context};

use aos_hub_core::storage_authority::lease::{
    BoundedLeaseRevocationPolicy, EpochLeaseFloor, EpochLeaseIssuerJournal, EpochLeaseSigningKey,
    LeaseClock, LeaseEffect, LeaseInteger,
};

use super::*;
use crate::direct_upload::provider_capacity::{self, policy, Class};

async fn signed_read(expiry: i64) -> (super::super::config::Config, Vec<u8>, EpochLeaseFloor) {
    let mut config = super::super::tests::config();
    config.timing_profile.maximum_lifetime = LeaseInteger::new(120).unwrap();
    config.cohorts[1].allowed_effects = vec![LeaseEffect::Read];
    config.validate().unwrap();
    let clock = LeaseClock {
        observed_at: 100,
        uncertainty: 2,
    };
    let journal = RefCell::new(
        EpochLeaseIssuerJournal::initialize_fresh_namespace(
            &config.publications[0],
            &config.executor_identity,
            BoundedLeaseRevocationPolicy {
                timing_profile: config.timing_profile.clone(),
            },
            clock,
        )
        .unwrap(),
    );
    let prepared = journal
        .borrow()
        .prepare_issue(
            &config.publications[0],
            config.cohorts[1].clone(),
            &config.issuer_key_id,
            expiry,
            clock,
        )
        .unwrap();
    let key = EpochLeaseSigningKey::from_bytes(config.issuer_key_id.clone(), &[7; 32]).unwrap();
    let bytes = prepared
        .commit_and_sign(
            &key,
            |transition| {
                let journal = &journal;
                async move {
                    ensure!(
                        *journal.borrow() == transition.expected,
                        "fixture CAS changed"
                    );
                    *journal.borrow_mut() = transition.next;
                    Ok(())
                }
            },
            || Ok(clock),
        )
        .await
        .unwrap();
    let floor = EpochLeaseFloor::initialize_fresh_guard(
        config.publications[0].authority.clone(),
        config.executor_identity.clone(),
        "managed/binding/objects/blob".into(),
        &config.timing_profile,
        clock,
    )
    .unwrap();
    (config, bytes, floor)
}

fn validate(
    config: &super::super::config::Config,
    bytes: &[u8],
    floor: &EpochLeaseFloor,
    now: i64,
) -> Result<ValidatedEpochLease> {
    config.verifier()?.validate_lease(
        bytes,
        &config.cohorts[1],
        &config.timing_profile,
        floor,
        &floor.full_key,
        LeaseEffect::Read,
        LeaseClock {
            observed_at: now,
            uncertainty: 2,
        },
    )
}

fn policy() -> policy::Policy {
    policy::Policy {
        version: 1,
        deployment_id: "fixture-deployment".into(),
        source_digest: "a".repeat(64),
        script_version: "fixture-script".into(),
        maximum_provider_requests: 3,
    }
}

#[tokio::test]
async fn signed_read_continues_past_dispatch_authentication_without_another_slot() {
    let (config, bytes, floor) = signed_read(220).await;
    let validated = validate(&config, &bytes, &floor, 101).unwrap();
    let window = ReadWindow::from_lease(&validated, &config.timing_profile, 2).unwrap();

    provider_capacity::configure(3).unwrap();
    let bulk = provider_capacity::acquire_class(1, Class::Bulk)
        .await
        .unwrap();
    let metadata = provider_capacity::acquire_class(1, Class::Metadata)
        .await
        .unwrap();
    let outer = policy::request::acquire(&policy(), Class::Bulk, &|| Ok(()))
        .await
        .unwrap();
    policy::request::validate_held(&policy(), &outer, &|| {
        window.check(101, false, &|| {
            validate(&config, &bytes, &floor, 101).map(|_| ())
        })
    })
    .unwrap();

    // An EOF 35 seconds later uses the same signed read lease and real owner,
    // independent of the request's already elapsed 30-second dispatch window.
    window
        .check(136, false, &|| {
            validate(&config, &bytes, &floor, 136).map(|_| ())
        })
        .unwrap();
    assert_eq!(window.remaining(136).unwrap(), 82);
    assert_eq!(provider_capacity::observation().active, 3);
    drop(outer);
    assert_eq!(provider_capacity::observation().active, 2);
    drop(metadata);
    drop(bulk);
    assert_eq!(provider_capacity::observation().active, 0);
}

#[tokio::test]
async fn cached_window_current_refusal_and_cancellation_release_owned_capacity() {
    let (config, bytes, floor) = signed_read(140).await;
    let validated = validate(&config, &bytes, &floor, 101).unwrap();
    let window = ReadWindow::from_lease(&validated, &config.timing_profile, 2).unwrap();
    assert!(window.check(138, false, &|| Ok(())).is_err());

    let mut denied = floor.clone();
    denied.generation = validated.payload.cohort.admission_generation;
    denied.admission_digest = Some(validated.payload.cohort.admission_digest.clone());
    denied.publication_digest = Some(validated.payload.cohort.publication_digest.clone());
    denied.denied = true;
    assert!(window
        .check(110, false, &|| {
            validate(&config, &bytes, &denied, 110).map(|_| ())
        })
        .is_err());
    let mut changed = config.clone();
    changed.cohorts[1].association.binding_resource_version = LeaseInteger::new(99).unwrap();
    assert!(window
        .check(110, false, &|| {
            validate(&changed, &bytes, &floor, 110).map(|_| ())
        })
        .is_err());
    assert!(window.check(110, true, &|| Ok(())).is_err());

    provider_capacity::configure(3).unwrap();
    let permit = policy::request::acquire(&policy(), Class::Bulk, &|| Ok(()))
        .await
        .unwrap();
    let mut pending = Box::pin(async move {
        let _owner = permit;
        futures_util::future::pending::<()>().await;
    });
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(pending.as_mut().poll(&mut context).is_pending());
    assert_eq!(provider_capacity::observation().active, 1);
    drop(pending);
    assert_eq!(provider_capacity::observation().active, 0);
    provider_capacity::configure(4).unwrap();
    provider_capacity::configure(3).unwrap();
}

#[tokio::test]
async fn unsupported_profiles_clock_bounds_and_lifetimes_refuse_without_truncation() {
    let (config, bytes, floor) = signed_read(220).await;
    let validated = validate(&config, &bytes, &floor, 101).unwrap();
    let mut substituted = config.timing_profile.clone();
    substituted.review_digest = "f".repeat(64);
    assert!(ReadWindow::from_lease(&validated, &substituted, 2).is_err());
    assert!(ReadWindow::from_lease(&validated, &config.timing_profile, 3).is_err());

    assert!(ReadWindow::checked(100, 100, 120, 2, 2).is_err());
    assert!(ReadWindow::checked(100, 221, 120, 2, 2).is_err());
    assert!(ReadWindow::checked(100, 220, i64::MAX, 2, 2).is_err());
    let timer_limit = i64::from(i32::MAX) / 1000;
    assert!(ReadWindow::checked(100, 220, timer_limit + 1, 2, 2).is_err());
    let window = ReadWindow::checked(100, 220, timer_limit, 2, 2).unwrap();
    assert!(window.remaining(i64::MAX).is_err());
    assert!(window.remaining(-1).is_err());
}
