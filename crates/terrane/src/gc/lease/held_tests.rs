//! Qualifies genuine held-context lease renewal against actual native storage.

#[path = "held_tests/support.rs"]
mod support;

#[path = "held_tests/output_sync.rs"]
mod output_sync;

use super::*;
use crate::gc::runner::CollectionError;
use crate::store::{Clock, EffectFault, StoreErrorKind};
use std::sync::Arc;
use std::time::Duration;
use support::*;
use terrane_core::gc::GcLease;

fn lease_error(error: &CollectionError) -> Option<&StoreFailure> {
    match error {
        CollectionError::Lease(LeaseError::Store(failure)) => Some(failure),
        CollectionError::Store(failure) => Some(failure),
        _ => None,
    }
}

fn denied(error: &CollectionError) -> bool {
    lease_error(error)
        .is_some_and(|failure| matches!(failure.kind(), StoreErrorKind::Denied { .. }))
}

#[tokio::test]
async fn held_renewal_reuses_actual_namespace_and_controls() {
    let fixture = Fixture::new().await;
    let (mut session, initial) = fixture.session().await;
    let collector = fixture.collector();
    let exclusion = collector.hold_namespace().await.require();
    let held = exclusion.destination();
    let before = held.observe_publication_unrepaired().await.require();
    let old_state = before.state().clone();
    let old_logical = before.logical().clone();
    drop(before);
    let retained = fixture.retained(&held).await;
    assert_excluded(&fixture.lock_paths());
    let acquisitions = fixture.fs.locks();
    let mut context = collector.held(&held, Some(&retained)).await.require();
    assert_eq!(fixture.fs.locks(), acquisitions);
    assert_excluded(&fixture.lock_paths());

    for (wall, ticks, expiry, revision) in [
        (105, 5, 140, initial.revision + 1),
        (125, 25, 160, initial.revision + 2),
    ] {
        fixture.base.clock.set(wall, ticks);
        session.renew_held(&mut context).await.require();
        let after = held.observe_publication_unrepaired().await.require();
        let expected = GcLease {
            holder: "held".into(),
            epoch: initial.lease.epoch,
            expiry,
        };
        assert_eq!(session.lease(), &expected);
        assert_eq!(after.state().revision, revision);
        let mut state = after.state().clone();
        state.revision = old_state.revision;
        assert_eq!(state, old_state);
        let mut logical = old_logical.clone();
        logical.insert("gc/lease".into(), Some(expected.encode().require()));
        assert_eq!(after.logical(), &logical);
        assert_eq!(fixture.fs.locks(), acquisitions);
        assert_excluded(&fixture.lock_paths());
    }
}

#[tokio::test]
async fn held_renewal_requires_exact_live_whole_lease() {
    for changed in 0..3 {
        let fixture = Fixture::new().await;
        let (_, mut receipt) = fixture.session().await;
        match changed {
            0 => receipt.lease.holder = "other".into(),
            1 => receipt.lease.epoch += 1,
            _ => receipt.lease.expiry += 1,
        }
        let mut session = crate::gc::runner::session::Session::from_receipt(
            receipt,
            20,
            fixture.base.clock.retain_native_clock().require(),
        )
        .require();
        let collector = fixture.collector();
        let exclusion = collector.hold_namespace().await.require();
        let held = exclusion.destination();
        let mut context = collector.held(&held, None).await.require();
        fixture.base.fs.reset();

        assert!(matches!(
            session.renew_held(&mut context).await,
            Err(CollectionError::Lease(LeaseError::Lease(
                terrane_core::gc::GcError::LeaseLost
            )))
        ));
        assert_eq!(fixture.fs.effects(), 0);
        assert!(session.recheck().is_err());
    }
}

#[tokio::test]
async fn held_renewal_acknowledges_only_actual_durable_success() {
    // Each failure occurs in the actual closed native acknowledgment, after
    // visible selection. Visible bytes cannot replace its empty result channel.
    for case in 0..13 {
        let fixture = Fixture::new().await;
        let (mut session, initial) = fixture.session().await;
        let collector = fixture.collector();
        let exclusion = collector.hold_namespace().await.require();
        let held = exclusion.destination();
        let mut context = collector.held(&held, None).await.require();
        fixture.base.clock.set(105, 5);
        if case == 0 {
            fixture.fs.noop();
        } else {
            let fault = match (case - 1) / 2 {
                0 => EffectFault::BeforeFileSync,
                1 => EffectFault::AfterFileSync,
                2 => EffectFault::BeforeDirectorySyncAt(fixture.base.config.root.clone()),
                3 => EffectFault::AfterDirectorySyncAt(fixture.base.config.root.clone()),
                4 => EffectFault::BeforeDirectorySyncAt(fixture.base.parent.join("publication")),
                _ => EffectFault::AfterDirectorySyncAt(fixture.base.parent.join("publication")),
            };
            fixture.fs.fault(fault, case % 2 == 0);
        }

        let error = session.renew_held(&mut context).await.require_error();
        fixture.fs.assert_consumed();
        let failure = lease_error(&error).require();
        if case == 0 || case % 2 == 0 {
            assert!(matches!(failure.kind(), StoreErrorKind::Unsupported));
        } else {
            assert!(matches!(failure.kind(), StoreErrorKind::Unavailable { .. }));
            assert!(std::error::Error::source(failure).is_some());
        }
        assert_eq!(session.lease(), &initial.lease);
        assert!(session.recheck().is_err());
        let after = held.observe_publication_unrepaired().await.require();
        assert_eq!(after.state().revision, initial.revision + 1);
        assert_eq!(
            GcLease::decode(after.logical()["gc/lease"].as_deref().require())
                .require()
                .expiry,
            140
        );
    }
}

#[tokio::test]
async fn held_renewal_preserves_clock_continuity_and_old_expiry() {
    for (wall, ticks) in [(120, 20), (104, 5), (105, 4)] {
        let fixture = Fixture::new().await;
        let (mut session, initial) = fixture.session().await;
        fixture.base.clock.set(105, 5);
        let (arrived, release) = fixture.fs.pause();
        let guard = Arc::clone(&fixture.guard);
        let authority = fixture.base.authority.clone();
        let worker = tokio::spawn(async move {
            let collector = Collector::new(guard.as_ref(), &authority);
            let exclusion = collector.hold_namespace().await.require();
            let held = exclusion.destination();
            let mut context = collector.held(&held, None).await.require();
            let result = session.renew_held(&mut context).await;
            (session, result)
        });
        arrival(arrived).await;
        fixture.base.clock.set(wall, ticks);
        release.send(()).require();

        let (session, result) = worker.await.require();
        assert!(denied(&result.require_error()));
        assert_eq!(session.lease(), &initial.lease);
        assert!(session.recheck().is_err());
        fixture.fs.assert_consumed();
    }

    let fixture = Fixture::new().await;
    let (mut session, _) = fixture.session().await;
    let old_check = session.owned_check();
    let collector = fixture.collector();
    let exclusion = collector.hold_namespace().await.require();
    let held = exclusion.destination();
    let mut context = collector.held(&held, None).await.require();
    fixture.base.clock.set(105, 5);
    session.renew_held(&mut context).await.require();
    fixture.base.clock.set(125, 25);
    assert!(session.owned_check()().is_ok());
    assert!(old_check().is_err());
}

#[tokio::test]
async fn held_renewal_refreshes_only_acknowledged_lease_selection() {
    for changed in 0..3 {
        let fixture = Fixture::new().await;
        let (mut session, initial) = fixture.session().await;
        let collector = fixture.collector();
        let exclusion = collector.hold_namespace().await.require();
        let held = exclusion.destination();
        let mut context = collector.held(&held, None).await.require();
        fixture.base.clock.set(105, 5);
        session.renew_held(&mut context).await.require();
        let acknowledged = session.lease().clone();
        let path = match changed {
            0 => fixture.base.authority.control().join("registration.cbor"),
            1 => fixture.base.slot(initial.revision),
            _ => {
                let observed = held.observe_publication_unrepaired().await.require();
                held.selected_guard_snapshot_record(&observed)
                    .await
                    .require()
                    .require()
                    .path()
                    .to_owned()
            }
        };
        let bytes = std::fs::read(&path).require();
        let old = std::fs::symlink_metadata(&path).require();
        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, &bytes).require();
        std::fs::set_permissions(&replacement, old.permissions()).require();
        std::fs::rename(&replacement, &path).require();
        fixture.base.fs.reset();
        fixture.base.clock.set(110, 10);

        assert!(denied(
            &session.renew_held(&mut context).await.require_error()
        ));
        assert_eq!(session.lease(), &acknowledged);
        assert!(session.recheck().is_err());
        assert_eq!(fixture.fs.effects(), 0);
        assert_eq!(std::fs::read(&path).require(), bytes);
    }

    for selected_guard in [true, false] {
        let fixture = Fixture::new().await;
        let (mut session, initial) = fixture.session().await;
        let guard_digest = fixture.base.selected().await.0.guard.require();
        let suffix: String = guard_digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let changed = if selected_guard {
            fixture
                .base
                .parent
                .join("publication")
                .join(format!("publication/guards/{suffix}"))
        } else {
            fixture.base.authority.control().join("registration.cbor")
        };
        fixture.base.clock.set(105, 5);
        let (arrived, release) = fixture.fs.pause();
        let guard = Arc::clone(&fixture.guard);
        let authority = fixture.base.authority.clone();
        let worker = tokio::spawn(async move {
            let collector = Collector::new(guard.as_ref(), &authority);
            let exclusion = collector.hold_namespace().await.require();
            let held = exclusion.destination();
            let mut context = collector.held(&held, None).await.require();
            let result = session.renew_held(&mut context).await;
            (session, result)
        });
        arrival(arrived).await;
        let mut bytes = std::fs::read(&changed).require();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        std::fs::write(&changed, &bytes).require();
        release.send(()).require();

        let (session, result) = worker.await.require();
        let error = result.require_error();
        assert!(matches!(
            lease_error(&error).require().kind(),
            StoreErrorKind::Unavailable { .. }
        ));
        assert_eq!(session.lease(), &initial.lease);
        assert!(session.recheck().is_err());
        fixture.fs.assert_consumed();
        assert_eq!(std::fs::read(&changed).require(), bytes);
    }
}

#[tokio::test]
async fn held_renewal_cancellation_retains_exclusion_and_poisoning() {
    let fixture = Fixture::new().await;
    let (mut session, _) = fixture.session().await;
    let retained_check = session.owned_check();
    fixture.base.clock.set(105, 5);
    let (arrived, release) = fixture.fs.pause();
    let guard = Arc::clone(&fixture.guard);
    let authority = fixture.base.authority.clone();
    let worker = tokio::spawn(async move {
        let collector = Collector::new(guard.as_ref(), &authority);
        let exclusion = collector.hold_namespace().await.require();
        let held = exclusion.destination();
        let mut context = collector.held(&held, None).await.require();
        session.renew_held(&mut context).await
    });
    arrival(arrived).await;
    worker.abort();
    assert!(worker.await.require_error().is_cancelled());
    assert!(retained_check().is_err());
    fixture.fs.assert_consumed();
    assert_excluded(&fixture.lock_paths());

    release.send(()).require();
    for path in fixture.lock_paths() {
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .require();
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || contender.lock()),
        )
        .await
        .require()
        .require()
        .require();
    }
    assert!(retained_check().is_err());
}
