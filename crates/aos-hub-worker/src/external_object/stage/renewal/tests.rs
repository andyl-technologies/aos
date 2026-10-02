//! Concurrent ownership and deadline tests of the production renewal helper.
//!
//! Issue closures here count controlled calls, not actual issuer RPCs, signing
//! CPU, durable commits or platform scale. No provider work is performed.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use super::*;

fn clock(now: i64) -> LeaseClock {
    LeaseClock {
        observed_at: now,
        uncertainty: 2,
    }
}

fn lease(token: &str, now: i64) -> VerifiedLease {
    VerifiedLease {
        token: token.to_owned(),
        issued_at: now,
        not_after: now + 60,
        last_observed_at: now,
    }
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn renewal_custody_refuses_every_effect_role_before_retained_reuse() {
    assert!(validate_roles("renewal", "control", "guard", Some("stage")).is_ok());
    assert!(validate_roles("renewal", "control", "guard", None).is_ok());
    for other_role in ["control", "guard", "stage"] {
        assert!(validate_roles(other_role, "control", "guard", Some("stage")).is_err());
    }
}

#[tokio::test]
async fn concurrent_same_cohort_has_one_owner_and_verified_result() {
    let pool = Rc::new(Renewals::default());
    let calls = Cell::new(0);
    let requests = (0..=MAX_FOLLOWERS).map(|_| {
        pool.acquire(
            "same-cohort".into(),
            || Ok(clock(100)),
            tokio::task::yield_now,
            |_| async {
                calls.set(calls.get() + 1);
                tokio::task::yield_now().await;
                Ok(lease("verified-original", 100))
            },
        )
    });

    let results = futures_util::future::join_all(requests).await;

    assert_eq!(calls.get(), 1);
    assert!(results
        .into_iter()
        .all(|value| value.unwrap() == "verified-original"));
    assert!(pool.flights.borrow().is_empty());
    let cached = pool
        .acquire(
            "same-cohort".into(),
            || Ok(clock(101)),
            tokio::task::yield_now,
            |_| async { panic!("cache hit dispatched") },
        )
        .await
        .unwrap();
    assert_eq!(cached, "verified-original");
}

#[tokio::test]
async fn all_32_cohorts_progress_independently_and_the_next_slot_refuses() {
    let pool = Rc::new(Renewals::default());
    let now = Cell::new(100);
    let calls = Cell::new(0);
    let mut requests = (0..MAX_COHORTS)
        .map(|index| {
            Box::pin(pool.acquire(
                format!("cohort-{index}"),
                || Ok(clock(now.get())),
                tokio::task::yield_now,
                |_| async {
                    calls.set(calls.get() + 1);
                    std::future::pending::<Result<VerifiedLease>>().await
                },
            ))
        })
        .collect::<Vec<_>>();
    for request in &mut requests {
        assert!(poll_once(request.as_mut()).is_pending());
    }
    assert_eq!(calls.get(), MAX_COHORTS);
    assert!(pool
        .acquire(
            "overflow".into(),
            || Ok(clock(now.get())),
            tokio::task::yield_now,
            |_| async { panic!("full pool dispatched") }
        )
        .await
        .is_err());
    drop(requests);
    assert_eq!(pool.flights.borrow().len(), MAX_COHORTS);

    now.set(128); // Conservative latest observation is the exclusive expiry.
    let result = pool
        .acquire(
            "fresh".into(),
            || Ok(clock(now.get())),
            tokio::task::yield_now,
            |_| async { Ok(lease("fresh-original", 128)) },
        )
        .await
        .unwrap();
    assert_eq!(result, "fresh-original");
    assert!(pool.flights.borrow().is_empty());
}

#[tokio::test]
async fn cancelled_owner_refuses_followers_and_new_attempts_until_original_expiry() {
    let pool = Rc::new(Renewals::default());
    let now = Cell::new(100);
    let calls = Cell::new(0);
    let mut owner = Box::pin(pool.acquire(
        "cohort".into(),
        || Ok(clock(now.get())),
        tokio::task::yield_now,
        |_| async {
            calls.set(calls.get() + 1);
            std::future::pending::<Result<VerifiedLease>>().await
        },
    ));
    assert!(poll_once(owner.as_mut()).is_pending());
    let mut follower = Box::pin(pool.acquire(
        "cohort".into(),
        || Ok(clock(now.get())),
        tokio::task::yield_now,
        |_| async { panic!("follower took ownership") },
    ));
    assert!(poll_once(follower.as_mut()).is_pending());

    drop(owner);
    assert!(follower.await.is_err());
    assert!(pool
        .acquire(
            "cohort".into(),
            || Ok(clock(now.get())),
            tokio::task::yield_now,
            |_| async { panic!("cancelled flight retried") }
        )
        .await
        .is_err());
    assert_eq!(calls.get(), 1);
    assert_eq!(pool.flights.borrow().len(), 1);

    now.set(128);
    let token = pool
        .acquire(
            "cohort".into(),
            || Ok(clock(now.get())),
            tokio::task::yield_now,
            |window| {
                assert_eq!(window.issued_at, 128);
                assert_eq!(window.expires_at, 158);
                async {
                    calls.set(calls.get() + 1);
                    Ok(lease("distinct-fresh-original", 128))
                }
            },
        )
        .await
        .unwrap();
    assert_eq!(token, "distinct-fresh-original");
    assert_eq!(calls.get(), 2);
}

#[tokio::test]
async fn issuer_error_does_not_elect_or_retry_an_owner() {
    let pool = Rc::new(Renewals::default());
    let calls = Cell::new(0);
    let first = pool
        .acquire(
            "cohort".into(),
            || Ok(clock(100)),
            tokio::task::yield_now,
            |_| async {
                calls.set(calls.get() + 1);
                anyhow::bail!("controlled lost reply")
            },
        )
        .await;
    assert!(first.is_err());
    let second = pool
        .acquire(
            "cohort".into(),
            || Ok(clock(120)),
            tokio::task::yield_now,
            |_| async { panic!("error retried") },
        )
        .await;
    assert!(second.is_err());
    assert_eq!(calls.get(), 1);
}

#[tokio::test]
async fn original_deadline_drops_pending_work_and_late_positive_is_not_cached() {
    struct Dropped<'a>(&'a Cell<bool>);
    impl Drop for Dropped<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }
    let pool = Rc::new(Renewals::default());
    let now = Cell::new(100);
    let dropped = Cell::new(false);
    let result = pool
        .acquire(
            "cohort".into(),
            || Ok(clock(now.get())),
            || async {
                now.set(128);
            },
            |_| async {
                let _pending = Dropped(&dropped);
                std::future::pending::<Result<VerifiedLease>>().await
            },
        )
        .await;
    assert!(result.is_err());
    assert!(dropped.get());
    assert!(pool.cache.borrow().is_empty());

    let late = pool
        .acquire(
            "other".into(),
            || Ok(clock(now.get())),
            tokio::task::yield_now,
            |_| async {
                now.set(156);
                Ok(lease("late-positive", 128))
            },
        )
        .await;
    assert!(late.is_err());
    assert!(pool.cache.borrow().is_empty());
}

#[test]
fn followers_keep_the_owner_deadline_and_exact_admission_bound() {
    let pool = Rc::new(Renewals::default());
    let owner = pool.join("cohort", clock(100)).unwrap();
    let followers = (0..MAX_FOLLOWERS)
        .map(|_| pool.join("cohort", clock(110)).unwrap())
        .collect::<Vec<_>>();
    assert!(followers
        .iter()
        .all(|ticket| ticket.expires_at == 130 && !ticket.owner));
    assert!(pool.join("cohort", clock(110)).is_err());
    drop(owner);
    assert!(matches!(
        *followers[0].flight.outcome.borrow(),
        Outcome::Unavailable
    ));
}

#[tokio::test]
async fn attestation_capped_short_reply_is_fresh_but_not_reused_as_cached_permission() {
    let pool = Rc::new(Renewals::default());
    let calls = Cell::new(0);
    for _ in 0..2 {
        let token = pool
            .acquire(
                "short".into(),
                || Ok(clock(100)),
                tokio::task::yield_now,
                |_| async {
                    calls.set(calls.get() + 1);
                    let mut value = lease("short-positive", 100);
                    value.not_after = 104;
                    Ok(value)
                },
            )
            .await
            .unwrap();
        assert_eq!(token, "short-positive");
    }
    assert_eq!(calls.get(), 2);
}

#[tokio::test]
async fn rollback_or_stale_token_refuses_before_reuse_or_dispatch() {
    let pool = Rc::new(Renewals::default());
    pool.acquire(
        "cohort".into(),
        || Ok(clock(100)),
        tokio::task::yield_now,
        |_| async { Ok(lease("original", 100)) },
    )
    .await
    .unwrap();
    assert!(pool
        .acquire(
            "cohort".into(),
            || Ok(clock(99)),
            tokio::task::yield_now,
            |_| async { panic!("rollback dispatched") }
        )
        .await
        .is_err());
    assert!(pool
        .acquire(
            "other".into(),
            || Ok(clock(101)),
            tokio::task::yield_now,
            |_| async { Ok(lease("stale-positive", 10)) }
        )
        .await
        .is_err());
    assert!(pool
        .acquire(
            "overflow".into(),
            || Ok(clock(i64::MAX)),
            tokio::task::yield_now,
            |_| async { panic!("overflow dispatched") }
        )
        .await
        .is_err());
}

#[tokio::test]
async fn context_or_renewal_material_substitution_never_borrows_another_token() {
    let context = serde_json::json!({
        "installation": "original", "prefix": "exact", "issuer_key_id": "key-one",
        "issuer_public_key": "public-one", "timing_profile": "profile-one",
        "clock_uncertainty": 2, "cohort": "cohort-one",
    });
    let key = coordination_key(&context, "renewal-one").unwrap();
    let pool = Rc::new(Renewals::default());
    pool.acquire(
        key.clone(),
        || Ok(clock(100)),
        tokio::task::yield_now,
        |_| async { Ok(lease("original-only", 100)) },
    )
    .await
    .unwrap();

    for field in context.as_object().unwrap().keys() {
        let mut changed = context.clone();
        changed[field] = "substitution".into();
        let changed_key = coordination_key(&changed, "renewal-one").unwrap();
        assert_ne!(key, changed_key);
        assert_eq!(
            pool.acquire(
                changed_key,
                || Ok(clock(100)),
                tokio::task::yield_now,
                |_| async { Ok(lease("distinct", 100)) }
            )
            .await
            .unwrap(),
            "distinct"
        );
    }
    let changed_key = coordination_key(&context, "renewal-two").unwrap();
    assert_ne!(key, changed_key);
    assert_eq!(
        pool.acquire(
            changed_key,
            || Ok(clock(100)),
            tokio::task::yield_now,
            |_| async { Ok(lease("changed-custody", 100)) }
        )
        .await
        .unwrap(),
        "changed-custody"
    );
}
