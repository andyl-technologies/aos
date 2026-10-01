//! Exercises exact Pending restart and retained genesis effects after cancellation.

#![allow(
    clippy::unwrap_used,
    reason = "Native fixture assertions intentionally panic."
)]

use super::super::fresh::{
    activate, bootstrap,
    test_fs::{Gate, ProbeFs, Stop},
    tests::{Fixture, Validator},
};
use crate::bucket::FileBucket;
use crate::store::{LocalFs, StoreErrorKind, TokioClock, TokioLocalFs};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::time::Duration;
use terrane_core::bucket::BucketKey;
use terrane_core::gc::publication::{Activation, BackendRegistration, PublicationCommit};

fn assert_coordination_contended(fixture: &Fixture) {
    let path = fixture
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .unwrap();
    let named = std::fs::symlink_metadata(&path).unwrap();
    let opened = contender.metadata().unwrap();
    assert_eq!((named.dev(), named.ino()), (opened.dev(), opened.ino()));
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
}

#[tokio::test]
async fn pending_restart_reuses_exact_staged_transaction_and_operation_nonce() {
    let fixture = Fixture::new();
    let receipt = fixture.staged().await;
    let transaction_key = format!(
        "publication/transactions/{}",
        bootstrap::operation(&receipt.staged)
    );
    let transaction = std::fs::read(fixture.control.join(&transaction_key)).unwrap();
    let pointer = std::fs::read(fixture.root.join("publication/PORTABLE")).unwrap();
    drop(receipt);

    let bucket = FileBucket::open(fixture.config(), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
    let commit = PublicationCommit::decode(
        &std::fs::read(fixture.control.join("publication/commits/0")).unwrap(),
    )
    .unwrap();
    assert_eq!(commit.transaction_key, transaction_key);
    assert_eq!(
        std::fs::read(fixture.control.join(&commit.transaction_key)).unwrap(),
        transaction
    );
    let recorded =
        terrane_core::gc::publication::PublicationTransaction::decode(&transaction).unwrap();
    assert_eq!(recorded.snapshot.encode().unwrap(), pointer);
    assert_eq!(bucket.root(), fixture.root);
}

#[tokio::test]
async fn pending_restart_recovers_before_and_after_actual_genesis_slot() {
    for stop in [Stop::BeforeSlot, Stop::AfterSlot] {
        let fixture = Fixture::new();
        let receipt = fixture.staged().await;
        let transaction_key = format!(
            "publication/transactions/{}",
            bootstrap::operation(&receipt.staged)
        );
        let transaction = std::fs::read(fixture.control.join(&transaction_key)).unwrap();
        let after_slot = matches!(stop, Stop::AfterSlot);
        let fs = ProbeFs::default();
        fs.stop(stop);

        let error = activate(&fs, receipt).await.err().unwrap();
        assert!(matches!(error.kind(), StoreErrorKind::Unavailable { .. }));
        let registration = BackendRegistration::decode(
            &std::fs::read(fixture.control.join("backend-registration.cbor")).unwrap(),
        )
        .unwrap();
        assert_eq!(registration.activation, Activation::Pending);
        let slot = std::fs::symlink_metadata(fixture.control.join("publication/commits/0"));
        if after_slot {
            assert!(slot.is_ok());
        } else {
            assert!(matches!(slot, Err(error) if error.kind() == std::io::ErrorKind::NotFound));
        }
        assert_eq!(fs.ordinary_effects(), 0);

        FileBucket::open(fixture.config(), TokioLocalFs, TokioClock, Validator)
            .await
            .unwrap();
        let commit = PublicationCommit::decode(
            &std::fs::read(fixture.control.join("publication/commits/0")).unwrap(),
        )
        .unwrap();
        assert_eq!(commit.transaction_key, transaction_key);
        assert_eq!(
            std::fs::read(fixture.control.join(transaction_key)).unwrap(),
            transaction
        );
    }
}

#[tokio::test]
async fn fresh_handoff_refuses_same_bytes_replacement_of_original_staged_leaf() {
    let fixture = Fixture::new();
    let receipt = fixture.staged().await;
    let transaction_key = format!(
        "publication/transactions/{}",
        bootstrap::operation(&receipt.staged)
    );
    let transaction_path = fixture.control.join(&transaction_key);
    let original = std::fs::read(&transaction_path).unwrap();
    let before = std::fs::symlink_metadata(&transaction_path).unwrap();
    let replacement = fixture.control.join("replacement");
    std::fs::write(&replacement, &original).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::rename(&replacement, &transaction_path).unwrap();
    let after = std::fs::symlink_metadata(&transaction_path).unwrap();
    assert_ne!((before.dev(), before.ino()), (after.dev(), after.ino()));

    activate(&TokioLocalFs, receipt).await.err().unwrap();
    assert_eq!(std::fs::read(transaction_path).unwrap(), original);
    assert!(matches!(
        std::fs::symlink_metadata(fixture.control.join("publication/commits/0")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_running_genesis_slot_retains_actual_receipts_until_worker_acknowledgment() {
    let fixture = Fixture::new();
    let receipt = fixture.staged().await;
    let directories = std::sync::Arc::downgrade(&receipt.directories);
    let fs = ProbeFs::default();
    let (arrived, received) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    fs.gate(Gate {
        arrived,
        release: released,
    });
    let activation = tokio::spawn(async move { activate(&fs, receipt).await });
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::task::spawn_blocking(move || received.recv().unwrap()),
    )
    .await
    .unwrap()
    .unwrap();

    activation.abort();
    assert!(activation.await.err().unwrap().is_cancelled());
    assert!(directories.upgrade().is_some());
    assert_coordination_contended(&fixture);
    release.send(()).unwrap();
    let lock = fixture
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let guard = tokio::time::timeout(
        Duration::from_secs(30),
        TokioLocalFs.lock_existing_exclusive(&lock),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(directories.upgrade().is_none());
    drop(guard);

    FileBucket::open(fixture.config(), TokioLocalFs, TokioClock, Validator)
        .await
        .unwrap();
}

#[test]
fn canceled_queued_genesis_effect_retains_actual_receipts_without_rebinding() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let fixture = Fixture::new();
        let receipt = match fixture.request().execute_inline().unwrap() {
            crate::store::NativePublicationInitializationOutcome::Fresh(receipt) => *receipt,
            crate::store::NativePublicationInitializationOutcome::Existing => {
                panic!("absent fixture was not created")
            }
        };
        let directories = std::sync::Arc::downgrade(&receipt.directories);
        let (arrived, received) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            arrived.send(()).unwrap();
            released.recv().unwrap();
        });
        received.recv_timeout(Duration::from_secs(30)).unwrap();
        let activation = tokio::spawn(async move { activate(&TokioLocalFs, receipt).await });
        tokio::task::yield_now().await;
        activation.abort();
        assert!(activation.await.err().unwrap().is_cancelled());
        assert!(directories.upgrade().is_some());
        assert_coordination_contended(&fixture);

        release.send(()).unwrap();
        blocker.await.unwrap();
        let lock = fixture
            .root
            .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
        let guard = tokio::time::timeout(
            Duration::from_secs(30),
            TokioLocalFs.lock_existing_exclusive(&lock),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(directories.upgrade().is_none());
        drop(guard);
        FileBucket::open(fixture.config(), TokioLocalFs, TokioClock, Validator)
            .await
            .unwrap();
    });
}
