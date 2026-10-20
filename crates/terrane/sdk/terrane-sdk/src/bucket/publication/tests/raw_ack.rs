//! Checks native Raw acknowledgments through real held publication and faults.
//!
//! Every fixture initializes a real backend. Negative adapters intercept only
//! the opaque final Raw request; they never fill its private result channel.
//! A selected successor after failure remains an indeterminate operation.

mod fixture;

use crate::bucket::held::SingleHeld;
use crate::store::{EffectFault, StoreErrorKind, StoreFailure};
use fixture::{
    Action, Failure, NativeError, artifacts, before, fixture, publish, replace_same_bytes, signal,
};
use std::{error::Error, io, sync::mpsc, time::Duration};

fn failed<T>(result: Result<T, StoreFailure>) -> Result<StoreFailure, Failure> {
    result
        .err()
        .ok_or_else(|| io::Error::other("Raw publication unexpectedly acknowledged").into())
}

fn unavailable(error: &StoreFailure, actual: &[NativeError], message: &str) {
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(actual.len(), 1);
    assert_eq!(actual[0].io_kind, Some(io::ErrorKind::Other));
    assert_eq!(actual[0].message, message);
    let source = error.source();
    assert!(source.is_some_and(|source| source.to_string() == message));
}

#[tokio::test]
async fn raw_publication_uses_actual_selected_slot_and_complete_durability() -> Result<(), Failure>
{
    let fixture = fixture().await?;
    let prior = before(&fixture.bucket).await?;
    let (arrived, arrival) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (synchronized, synchronization) = mpsc::channel();
    release.send(())?;
    fixture.fs.arm(
        fixture.slot(),
        Action::Handoff {
            before: arrived,
            release: released,
            after: synchronized,
        },
    )?;

    let receipt = publish(&fixture.bucket).await?;

    signal(arrival).await?;
    signal(synchronization).await?;
    fixture.fs.consumed()?;
    assert_eq!(fixture.fs.slots()?, vec![fixture.slot()]);
    assert!(fixture.fs.errors()?.is_empty());
    assert_eq!(receipt.stamp, artifacts(&fixture, &prior).await?);
    assert_eq!(receipt.state.revision, 1);
    fixture.reopen().await?;
    fixture.cleanup().await
}

#[tokio::test]
async fn raw_publication_noop_and_swallowed_sync_never_acknowledge() -> Result<(), Failure> {
    // Neither a no-op nor a swallowed genuine failure can fill the private
    // completion channel, even though the selecting slot already exists.
    for (action, expected_native_error) in [
        (Action::Noop, None),
        (
            Action::Swallow(EffectFault::BeforeFileSync),
            Some("injected creation file sync failure"),
        ),
        (
            Action::Swallow(EffectFault::BeforeDirectorySync),
            Some("injected creation directory sync failure"),
        ),
    ] {
        let fixture = fixture().await?;
        let prior = before(&fixture.bucket).await?;
        fixture.fs.arm(fixture.slot(), action)?;

        let error = failed(publish(&fixture.bucket).await)?;

        assert_eq!(error.kind(), &StoreErrorKind::Unsupported);
        assert!(error.source().is_some_and(
            |source| source.to_string() == "native raw publication acknowledgment unavailable"
        ));
        fixture.fs.consumed()?;
        assert_eq!(fixture.fs.slots()?, vec![fixture.slot()]);
        let actual = fixture.fs.errors()?;
        match expected_native_error {
            Some(message) => {
                assert_eq!(actual.len(), 1);
                assert_eq!(actual[0].io_kind, Some(io::ErrorKind::Other));
                assert_eq!(actual[0].message, message);
            }
            None => assert!(actual.is_empty()),
        }
        artifacts(&fixture, &prior).await?;
        fixture.reopen().await?;
        fixture.cleanup().await?;
    }

    // These paths are independent expected output ancestors, not a list copied
    // from RawRequest or its internal target inventory. Every required ancestor
    // must encounter a real sync fault rather than silently omit durability.
    let file = fixture().await?;
    let prior = before(&file.bucket).await?;
    file.fs
        .arm(file.slot(), Action::Fault(EffectFault::BeforeFileSync))?;
    let error = failed(publish(&file.bucket).await)?;
    unavailable(
        &error,
        &file.fs.errors()?,
        "injected creation file sync failure",
    );
    file.fs.consumed()?;
    artifacts(&file, &prior).await?;
    file.reopen().await?;
    file.cleanup().await?;

    for scope in [
        "control",
        "control/publication",
        "control/publication/commits",
        "control/publication/transactions",
        "root",
        "root/publication",
        "root/publication/snapshots",
        "root/refs",
        "root/refs/tags",
        "root/refs/tags/_",
    ] {
        let fixture = fixture().await?;
        let prior = before(&fixture.bucket).await?;
        let path = match scope.split_once('/') {
            Some(("control", suffix)) => fixture.control.join(suffix),
            Some(("root", suffix)) => fixture.bucket.root().join(suffix),
            None if scope == "control" => fixture.control.clone(),
            None => fixture.bucket.root().to_owned(),
            _ => return Err(io::Error::other("unknown fixed Raw directory case").into()),
        };
        fixture.fs.arm(
            fixture.slot(),
            Action::Fault(EffectFault::BeforeDirectorySyncAt(path)),
        )?;

        let error = failed(publish(&fixture.bucket).await)?;

        unavailable(
            &error,
            &fixture.fs.errors()?,
            "injected creation directory sync failure",
        );
        fixture.fs.consumed()?;
        artifacts(&fixture, &prior).await?;
        fixture.reopen().await?;
        fixture.cleanup().await?;
    }
    Ok(())
}

#[tokio::test]
async fn raw_publication_post_slot_failure_and_cancellation_preserve_uncertainty()
-> Result<(), Failure> {
    {
        let fixture = fixture().await?;
        let prior = before(&fixture.bucket).await?;
        fixture.fs.arm(
            fixture.slot(),
            Action::Fault(EffectFault::AfterDirectorySyncAt(
                fixture.bucket.root().to_owned(),
            )),
        )?;

        let error = failed(publish(&fixture.bucket).await)?;

        unavailable(
            &error,
            &fixture.fs.errors()?,
            "injected creation failure after directory sync",
        );
        fixture.fs.consumed()?;
        artifacts(&fixture, &prior).await?;
        fixture.reopen().await?;
        fixture.cleanup().await?;
    }

    // Publication owns the holder inside its task. Aborting that waiter drops
    // every borrowed async owner while the real blocking worker keeps exclusion.
    // The local task set also supports the ordinary non-Send native profile.
    tokio::task::LocalSet::new()
        .run_until(async {
            let fixture = fixture().await?;
            let prior = before(&fixture.bucket).await?;
            let (arrived, arrival) = mpsc::channel();
            let (release, released) = mpsc::channel();
            let (synchronized, synchronization) = mpsc::channel();
            fixture.fs.arm(
                fixture.slot(),
                Action::Handoff {
                    before: arrived,
                    release: released,
                    after: synchronized,
                },
            )?;
            let bucket = fixture.bucket.clone();
            let waiter = tokio::task::spawn_local(async move { publish(&bucket).await });
            signal(arrival).await?;
            assert!(fixture.slot().is_file());

            waiter.abort();
            let cancelled = waiter.await;
            assert!(cancelled.is_err_and(|error| error.is_cancelled()));
            fixture.fs.consumed()?;
            let bucket = fixture.bucket.clone();
            let mut next = tokio::task::spawn_local(async move {
                let holder = SingleHeld::acquire(&bucket).await?;
                drop(holder);
                Ok::<(), StoreFailure>(())
            });
            assert!(
                tokio::time::timeout(Duration::from_millis(100), &mut next)
                    .await
                    .is_err()
            );

            release.send(())?;
            signal(synchronization).await?;
            tokio::time::timeout(Duration::from_secs(30), next).await???;

            artifacts(&fixture, &prior).await?;
            fixture.reopen().await?;
            fixture.cleanup().await
        })
        .await
}

#[tokio::test]
async fn raw_publication_retains_original_payload_and_control_incarnations() -> Result<(), Failure>
{
    tokio::task::LocalSet::new()
        .run_until(async {
            for retained in ["registration", "selected-slot", "unchanged-payload"] {
                let fixture = fixture().await?;
                let path = match retained {
                    "registration" => fixture.control.join("backend-registration.cbor"),
                    "selected-slot" => fixture.control.join("publication/commits/0"),
                    "unchanged-payload" => {
                        fixture.bucket.root().join("publication/SELECTED-HISTORY")
                    }
                    _ => return Err(io::Error::other("unknown fixed Raw preimage case").into()),
                };
                let original_bytes = std::fs::read(&path)?;
                let (arrived, arrival) = mpsc::channel();
                let (release, released) = mpsc::channel();
                let (synchronized, synchronization) = mpsc::channel();
                fixture.fs.arm(
                    fixture.slot(),
                    Action::Handoff {
                        before: arrived,
                        release: released,
                        after: synchronized,
                    },
                )?;
                let bucket = fixture.bucket.clone();
                let waiter = tokio::task::spawn_local(async move { publish(&bucket).await });
                signal(arrival).await?;

                // Native output files have reached the directory boundary;
                // changing a previously captured input must refuse before the
                // queued actual directory syscall and final acknowledgment.
                replace_same_bytes(&path)?;
                release.send(())?;
                let error = failed(waiter.await?)?;

                fixture.fs.consumed()?;
                assert_eq!(fixture.fs.slots()?, vec![fixture.slot()]);
                assert_eq!(
                    error.kind(),
                    &StoreErrorKind::Unavailable { retry_after: None }
                );
                let native = fixture.fs.errors()?;
                assert_eq!(native.len(), 1);
                assert_eq!(native[0].io_kind, Some(io::ErrorKind::Other));
                assert!(
                    error
                        .source()
                        .is_some_and(|source| source.to_string() == native[0].message)
                );
                assert_eq!(
                    synchronization.try_recv(),
                    Err(mpsc::TryRecvError::Disconnected)
                );
                assert_eq!(std::fs::read(&path)?, original_bytes);
                // Failure follows real slot selection; no successor is removed
                // and neither the failed caller nor this test claims rollback.
                assert!(fixture.slot().is_file());
                fixture.cleanup().await?;
            }
            Ok(())
        })
        .await
}
