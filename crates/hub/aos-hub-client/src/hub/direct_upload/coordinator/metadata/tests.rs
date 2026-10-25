//! Checks actual admitted-source custody while metadata passes a stalled batch.

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use aos_transfer::direct_upload::AdmittedSource;
use tokio::sync::{Barrier, Notify};

use super::*;

struct Descriptor {
    index: usize,
    source: Option<AdmittedSource>,
    live: Arc<AtomicUsize>,
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        drop(self.source.take());
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn metadata_crosses_descriptor_waves_without_exceeding_sixty_four_sources() {
    let mut original = tempfile::NamedTempFile::new().unwrap();
    original.write_all(b"abc").unwrap();
    let live = Arc::new(AtomicUsize::new(0));
    let peak = AtomicUsize::new(0);
    let staged = AtomicUsize::new(0);
    let started = AtomicUsize::new(0);
    let first_wave = Barrier::new(8);
    let release = Notify::new();

    let prepare = |index| {
        let live = Arc::clone(&live);
        let original = &original;
        let peak = &peak;
        async move {
            let count = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            let mut descriptor = Descriptor {
                index,
                source: None,
                live,
            };
            let file = std::fs::File::open(original.path()).unwrap();
            descriptor.source = Some(
                AdmittedSource::admit(
                    file,
                    3,
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    5 * 1024 * 1024,
                )
                .await
                .unwrap(),
            );
            Ok::<_, DirectClientError>(descriptor)
        }
    };
    let stage = |files: Vec<Descriptor>| {
        let staged = &staged;
        let started = &started;
        let first_wave = &first_wave;
        let release = &release;
        async move {
            if started.fetch_add(1, Ordering::SeqCst) < 8 {
                first_wave.wait().await;
            }
            if files[0].index == 0 {
                release.notified().await;
            } else {
                tokio::task::yield_now().await;
            }
            staged.fetch_add(files.len(), Ordering::SeqCst);
            Ok(())
        }
    };
    let uploads = run_batches((0..256).collect(), 8, prepare, stage);
    let release_after_later_waves = async {
        while staged.load(Ordering::SeqCst) < 128 {
            tokio::task::yield_now().await;
        }
        release.notify_one();
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(uploads, release_after_later_waves)
    })
    .await
    .expect("later inventory must progress while the first source batch remains held");

    result.unwrap();
    assert_eq!(staged.load(Ordering::SeqCst), 256);
    assert_eq!(peak.load(Ordering::SeqCst), 64);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_batch_geometry_never_opens_a_source() {
    for size in [0, MAX_DIRECT_BATCH_ITEMS + 1] {
        let result: Result<(), DirectClientError> = run_batches(
            vec![0],
            size,
            |_| -> std::future::Ready<Result<(), DirectClientError>> {
                panic!("invalid geometry admitted a source")
            },
            |_| -> std::future::Ready<Result<(), DirectClientError>> {
                panic!("invalid geometry dispatched staging")
            },
        )
        .await;

        assert_eq!(result, Err(DirectClientError::Invalid));
    }
}
