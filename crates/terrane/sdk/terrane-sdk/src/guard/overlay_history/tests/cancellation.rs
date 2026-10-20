//! Keeps both actual exclusions in a submitted overlay close after its waiter drops.

use super::*;
use crate::store::{LocalFs, TokioFileLock, TokioLocalFs};
use std::{path::Path, time::Duration};
use terrane_format::bucket::BucketKey;

const BOUND: Duration = Duration::from_secs(10);

struct Release(Option<std::sync::mpsc::Sender<()>>);

impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[tokio::test]
async fn overlay_history_cancelled_close_keeps_namespace_and_original_exclusions() -> TestResult {
    let fixture = Fixture::open().await?;
    let namespace = fixture
        .guard()
        .store()
        .root()
        .join(BucketKey::parse("CAPABILITIES")?.lock_name());
    let authority = fixture.guard().configured_original_authority()?;
    let control = authority.control().join("retention.lock");
    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let source = holder.source();
    let selected = source.observe_publication_ordinary_retained().await?;
    let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    let (entered, arrived) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    let mut release = Release(Some(release));
    *fixture.fs.projection_pause.lock().unwrap() = Some(fs::ProjectionPause { entered, released });
    let scope = HistoryObservation::held(selected.identity()).tracked(&consumed);
    let mut pending =
        Box::pin(guard.verified_overlay_layer_history_observed(fixture.layer.commit, scope));
    tokio::select! {
        result = &mut pending => panic!("overlay close did not reach submitted worker: {}", result.is_ok()),
        result = tokio::time::timeout(BOUND, arrived) => { result??; },
    }
    drop(pending);
    assert!(
        consumed
            .observed_completed_view_contexts_for_tests()?
            .is_empty()
    );
    drop(consumed);
    drop(guard);
    drop(selected);
    drop(source);
    drop(holder);
    for path in [&namespace, &control] {
        assert_eq!(
            TokioLocalFs
                .try_lock_existing_exclusive(path)
                .await
                .err()
                .ok_or("cancelled worker lost actual exclusion")?
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    if let Some(sender) = release.0.take() {
        let _ = sender.send(());
    }
    let (namespace_lock, control_lock) = tokio::time::timeout(BOUND, async {
        let namespace = acquire(&namespace).await?;
        let control = acquire(&control).await?;
        Ok::<_, std::io::Error>((namespace, control))
    })
    .await??;
    drop(control_lock);
    drop(namespace_lock);
    let holder = SingleHeld::acquire_read_only(fixture.guard().store()).await?;
    let source = holder.source();
    let selected = source.observe_publication_ordinary_retained().await?;
    let guard = fixture.guard().held_guard(holder.source(), TokioClock)?;
    let consumed = ConsumedResolver::new(&guard, &authority)?;
    guard
        .verified_overlay_layer_history_observed(
            fixture.layer.commit,
            HistoryObservation::held(selected.identity()).tracked(&consumed),
        )
        .await?;
    assert_eq!(
        consumed.observed_completed_view_contexts_for_tests()?.len(),
        2
    );
    Ok(())
}

async fn acquire(path: &Path) -> std::io::Result<TokioFileLock> {
    loop {
        match TokioLocalFs.try_lock_existing_exclusive(path).await {
            Ok(lock) => return Ok(lock),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(Duration::from_millis(10)).await
            }
            Err(error) => return Err(error),
        }
    }
}
