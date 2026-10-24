//! Retains real namespace and Original exclusions after submitted direct-close cancellation.

use super::{
    Mode,
    fixture::{Fixture, TestResult},
    fs::ProjectionPause,
};
use crate::store::{LocalFs, TokioFileLock, TokioLocalFs};
use std::{path::Path, time::Duration};
use terrane_format::bucket::BucketKey;

const BOUND: Duration = Duration::from_secs(10);

// Unwinding or an early return releases the actual blocking worker.
struct Release(Option<std::sync::mpsc::Sender<()>>);
impl Release {
    fn release(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for Release {
    fn drop(&mut self) {
        self.release();
    }
}

#[tokio::test]
async fn direct_history_submitted_closing_keeps_both_exclusions_after_cancellation() -> TestResult {
    for mode in [Mode::History, Mode::TreeAndHistory] {
        let fixture = Fixture::open().await?;
        let namespace = fixture
            .guard()
            .store()
            .root()
            .join(BucketKey::parse("CAPABILITIES")?.lock_name());
        let authority = fixture.guard().configured_original_authority()?;
        let control = authority.control().join("retention.lock");
        let (entered, arrived) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let mut release = Release(Some(release));
        *fixture.fs.projection_pause.lock().unwrap() = Some(ProjectionPause { entered, released });
        // There is no caller holder, fabricated capability or ref permission.
        // The actual direct factory and its submitted worker own every exclusion.
        let mut pending = Box::pin(mode.verify(&fixture));
        tokio::select! {
            entered = tokio::time::timeout(BOUND, arrived) => { entered??; }
            result = &mut pending => panic!("direct closing did not pause: {result:?}"),
        }
        drop(pending);
        assert_eq!(
            TokioLocalFs
                .try_lock_existing_exclusive(&namespace)
                .await
                .err()
                .ok_or("worker lost namespace exclusion")?
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            TokioLocalFs
                .try_lock_existing_exclusive(&control)
                .await
                .err()
                .ok_or("worker lost Original exclusion")?
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        release.release();
        let (namespace, control) = tokio::time::timeout(BOUND, async {
            let namespace = acquire(&namespace).await?;
            let control = acquire(&control).await?;
            Ok::<_, std::io::Error>((namespace, control))
        })
        .await??;
        drop(control);
        drop(namespace);
        assert_eq!(mode.verify(&fixture).await?.commits().count(), 2);
    }
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
