//! Checks exclusion continuity after cancelling a submitted native closing worker.

use super::fs::ProjectionPause;
use super::support::{Fixture, REFERENCE, TestResult};
use crate::bucket::held::SingleHeld;
use crate::guard::{ConsumedResolver, HistoryObservation};
use crate::ref_advance::tests::token;
use crate::store::{LocalFs, TokioClock, TokioFileLock, TokioLocalFs};
use std::path::Path;
use std::time::Duration;
use terrane_format::auth::Verb;
use terrane_format::bucket::BucketKey;

const BOUND: Duration = Duration::from_secs(10);

/// Releases the real blocking worker on success, early return or assertion panic.
struct WorkerRelease(Option<std::sync::mpsc::Sender<()>>);

impl WorkerRelease {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for WorkerRelease {
    fn drop(&mut self) {
        self.release();
    }
}

/// Cancels only after actual native projection entry and drops every caller hold.
///
/// # Errors
/// Preserves real setup, observation, lock, timeout and fresh authorization failures.
///
/// # Panics
/// Panics if cancelled history was promoted, a worker-owned exclusion is lost,
/// or the isolated observer mutex is poisoned.
pub(super) async fn check(fixture: &Fixture) -> TestResult {
    let namespace_lock = fixture
        .guard()
        .store()
        .root()
        .join(BucketKey::parse("CAPABILITIES")?.lock_name());
    let authority = fixture.guard().configured_original_authority()?;
    let control_lock = authority.control().join("retention.lock");
    let (release, released) = std::sync::mpsc::channel();
    let mut release = WorkerRelease(Some(release));

    {
        let source = fixture.guard();
        let holder = SingleHeld::acquire_read_only(source.store()).await?;
        let held = holder.source();
        let observed = held.observe_publication_ordinary_retained().await?;
        let mut controls = source
            .hold_original_registration(&authority, observed.identity())
            .await?;
        let retained = crate::guard::read::indexes::retention::capture(
            source,
            &authority,
            &mut controls,
            &held,
            &observed,
        )
        .await?;
        let guard = source.held_guard(holder.source(), TokioClock)?;
        guard.retain_original_controls(retained.controls())?;
        let identity = held.identity_proof();
        let consumed = ConsumedResolver::new(&guard, &authority)?;
        let capability = token();
        let history = HistoryObservation::held(&identity).tracked(&consumed);

        // Earlier capture is complete. This observer can only run inside the
        // genuine submitted closing projection, which owns exclusion duplicates.
        let (entered, arrived) = tokio::sync::oneshot::channel();
        *fixture.fs.projection_pause.lock().unwrap() = Some(ProjectionPause { entered, released });
        let mut authorization = Box::pin(guard.authorize_observed(
            REFERENCE,
            &capability,
            Verb::Read,
            &[],
            "sdk",
            history,
        ));
        tokio::select! {
            entered = tokio::time::timeout(BOUND, arrived) => { entered??; }
            result = &mut authorization => panic!("submitted closing worker did not pause: {result:?}"),
        }
        drop(authorization);
        assert!(
            consumed
                .observed_completed_view_contexts_for_tests()?
                .is_empty(),
            "a cancelled closing consumer cannot promote pending history"
        );
    }

    // No caller holder, adapter, Guard, selected observation, retained Original
    // receipt or control lock survives this scope. Only the real worker can now
    // explain both independently observed exclusions.
    assert_eq!(
        TokioLocalFs
            .try_lock_existing_exclusive(&namespace_lock)
            .await
            .err()
            .ok_or("submitted worker released namespace exclusion on cancellation")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        TokioLocalFs
            .try_lock_existing_exclusive(&control_lock)
            .await
            .err()
            .ok_or("submitted worker released Original exclusion on cancellation")?
            .kind(),
        std::io::ErrorKind::WouldBlock
    );

    release.release();
    let (namespace, control) = tokio::time::timeout(BOUND, async {
        let namespace = acquire_exclusive(&namespace_lock).await?;
        let control = acquire_exclusive(&control_lock).await?;
        Ok::<_, std::io::Error>((namespace, control))
    })
    .await??;
    drop(control);
    drop(namespace);

    let (authorized, _) = fixture.authorize().await?;
    assert_eq!(authorized.record(), Some(&fixture.head));
    Ok(())
}

// Independent contenders preserve namespace-before-control ordering and retry
// only contention while the genuine worker finishes its unchanged projection.
async fn acquire_exclusive(path: &Path) -> std::io::Result<TokioFileLock> {
    loop {
        match TokioLocalFs.try_lock_existing_exclusive(path).await {
            Ok(lock) => return Ok(lock),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error),
        }
    }
}
