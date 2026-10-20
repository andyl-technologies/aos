//! Refuses real unlink, durability and authority faults without synthetic acknowledgment.

use super::support::*;
use crate::gc::runner::CollectionError;
use crate::store::native_publication_effects::collection_local_deletion::DeletionBoundary;
use crate::store::{Clock, EffectFault, StoreErrorKind};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use terrane_format::gc::DeletePhase;
use tokio::sync::Semaphore;

async fn sync_fault(
    setup: &Semaphore,
    phase: DeletePhase,
    fault: EffectFault,
    source: &str,
    renamed: bool,
) {
    let permit = setup.acquire().await.require();
    let mut fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    drop(permit);

    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    let key = owned.authorization.operation_key();
    fixture.fs.fault(phase, fault);

    let error = collection
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require_error();

    let CollectionError::Store(error) = error else {
        panic!("expected actual native I/O failure: {error:?}")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(&error).require().to_string(),
        source
    );
    fixture.fs.assert_consumed();
    let actual = operation(&fixture, &key);
    assert_eq!(actual.authorization, owned.authorization);
    let expected = if renamed {
        match phase {
            DeletePhase::Invalidated => DeletePhase::PackAbsent,
            DeletePhase::PackAbsent => DeletePhase::IndexAbsent,
            DeletePhase::IndexAbsent => DeletePhase::ContainersConfirmed,
            DeletePhase::ContainersConfirmed => DeletePhase::Done,
            _ => panic!("fault matrix contains unsupported phase"),
        }
    } else {
        phase
    };
    assert_eq!(actual.phase, expected);
    drop(collection);
    fixture.reopen().await;
    let mut fresh = fresh_collection(&fixture, 301).await;
    let done = fresh
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require();
    assert_done(&fixture, &original, &owned, &done).await;
    drop(fresh);
    fixture.cleanup();
}

#[tokio::test]
async fn each_unlink_directory_and_progress_sync_fault_preserves_exact_recoverable_prefix() {
    // Bound native setup overlap while preserving concurrent real deletion waits.
    let setup = Semaphore::new(1);

    tokio::join!(
        sync_fault(
            &setup,
            DeletePhase::Invalidated,
            EffectFault::BeforeUnlink,
            "injected local unlink failure",
            false
        ),
        sync_fault(
            &setup,
            DeletePhase::Invalidated,
            EffectFault::AfterUnlink,
            "injected local failure after unlink",
            false
        ),
        sync_fault(
            &setup,
            DeletePhase::PackAbsent,
            EffectFault::BeforeDirectorySync,
            "injected creation directory sync failure",
            false
        ),
        sync_fault(
            &setup,
            DeletePhase::PackAbsent,
            EffectFault::BeforeFileSync,
            "injected creation file sync failure",
            false
        ),
        sync_fault(
            &setup,
            DeletePhase::IndexAbsent,
            EffectFault::AfterRename,
            "injected local failure after progress rename",
            true
        ),
        sync_fault(
            &setup,
            DeletePhase::ContainersConfirmed,
            EffectFault::BeforeUnlink,
            "injected local unlink failure",
            false
        ),
        sync_fault(
            &setup,
            DeletePhase::ContainersConfirmed,
            EffectFault::AfterUnlink,
            "injected local failure after unlink",
            false
        ),
    );
}

#[derive(Clone, Copy)]
enum Change {
    Expiry,
    Control,
    SameInode,
    Replacement,
}

async fn changed_handoff(phase: DeletePhase, boundary: DeletionBoundary, change: Change) {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    let key = owned.authorization.operation_key();
    let (arrived, release) = fixture.fs.pause(phase, boundary);
    let mut pending =
        Box::pin(collection.resume_local_delete(fixture.repository.coordinator(), &key));
    tokio::select! {
        result = &mut pending => panic!("operation completed before actual handoff: {result:?}"),
        () = arrival(arrived) => {}
    }
    let before_phase = operation(&fixture, &key);
    let before_presence = original.paths.each_ref().map(|path| path.exists());
    match change {
        Change::Expiry => {
            let wall = fixture
                .clock
                .now()
                .duration_since(std::time::UNIX_EPOCH)
                .require()
                .as_secs();
            fixture.clock.set(
                wall.checked_add(10_000).require(),
                fixture
                    .clock
                    .monotonic()
                    .as_secs()
                    .checked_add(10_000)
                    .require(),
            );
        }
        Change::Control => {
            let path = fixture.authority.control().join("registration.cbor");
            let bytes = std::fs::read(&path).require();
            let old = std::fs::symlink_metadata(&path).require();
            let temporary = path.with_extension("deletion-replacement");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .require();
            file.write_all(&bytes).require();
            file.sync_all().require();
            std::fs::rename(&temporary, &path).require();
            assert_ne!(std::fs::symlink_metadata(&path).require().ino(), old.ino());
        }
        Change::SameInode | Change::Replacement => {
            let index = if phase == DeletePhase::Invalidated {
                0
            } else {
                1
            };
            let path = &original.paths[index];
            let old = std::fs::symlink_metadata(path).require();
            if matches!(change, Change::SameInode) {
                let mut file = std::fs::OpenOptions::new().write(true).open(path).require();
                file.seek(SeekFrom::Start(0)).require();
                file.write_all(&[original.bodies[index][0] ^ 1]).require();
                file.sync_all().require();
                assert_eq!(std::fs::symlink_metadata(path).require().ino(), old.ino());
                assert_eq!(std::fs::symlink_metadata(path).require().len(), old.len());
            } else {
                let temporary = path.with_extension("deletion-replacement");
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&temporary)
                    .require();
                file.write_all(&original.bodies[index]).require();
                file.sync_all().require();
                std::fs::rename(&temporary, path).require();
                assert_ne!(std::fs::symlink_metadata(path).require().ino(), old.ino());
            }
        }
    }
    release.send(()).require();
    let error = pending.await.require_error();
    let CollectionError::Store(error) = error else {
        panic!("expected actual current/binding refusal: {error:?}")
    };
    match change {
        Change::Expiry => assert_eq!(
            error.kind(),
            &StoreErrorKind::Denied {
                verb: "gc-checkpoint",
                pattern: "current configured collector session".into(),
            }
        ),
        Change::Control => {
            assert_eq!(
                error.kind(),
                &StoreErrorKind::Unavailable { retry_after: None }
            );
            assert_eq!(
                std::error::Error::source(&error).require().to_string(),
                "exact read metadata changed"
            );
        }
        Change::SameInode | Change::Replacement => {
            assert_eq!(
                error.kind(),
                &StoreErrorKind::Unavailable { retry_after: None }
            );
            assert_eq!(
                std::error::Error::source(&error).require().to_string(),
                "owned artifact incarnation changed"
            );
        }
    }
    fixture.fs.assert_consumed();
    assert_eq!(operation(&fixture, &key), before_phase);
    assert_eq!(
        original.paths.each_ref().map(|path| path.exists()),
        before_presence
    );
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn each_handoff_refuses_current_expiry_control_change_and_replacement() {
    tokio::join!(
        changed_handoff(
            DeletePhase::Invalidated,
            DeletionBoundary::BeforeOpen,
            Change::Expiry
        ),
        changed_handoff(
            DeletePhase::PackAbsent,
            DeletionBoundary::BeforeDirectorySync,
            Change::Control
        ),
        changed_handoff(
            DeletePhase::PackAbsent,
            DeletionBoundary::BeforeOpen,
            Change::SameInode
        ),
        changed_handoff(
            DeletePhase::Invalidated,
            DeletionBoundary::BeforeOpen,
            Change::Replacement
        ),
        changed_handoff(
            DeletePhase::IndexAbsent,
            DeletionBoundary::AfterSourceSync,
            Change::Expiry
        ),
        changed_handoff(
            DeletePhase::ContainersConfirmed,
            DeletionBoundary::AfterDirectorySync,
            Change::Control
        ),
    );
}

async fn missing_ack(swallow: bool) {
    let fixture = Fixture::new().await;
    let (mut collection, requested) = retired(&fixture).await;
    let original = before(&fixture, &requested).await;
    fixture.clock.enable_timer();
    let owned = collection
        .own_local_pack(fixture.repository.coordinator(), requested)
        .await
        .require();
    let key = owned.authorization.operation_key();
    if swallow {
        fixture
            .fs
            .swallow(DeletePhase::Invalidated, EffectFault::BeforeFileSync);
    } else {
        fixture.fs.noop(DeletePhase::Invalidated);
    }

    let error = collection
        .resume_local_delete(fixture.repository.coordinator(), &key)
        .await
        .require_error();

    let CollectionError::Store(error) = error else {
        panic!("expected absent native acknowledgment: {error:?}")
    };
    assert_eq!(
        error.kind(),
        &StoreErrorKind::Unavailable { retry_after: None }
    );
    assert_eq!(
        std::error::Error::source(&error).require().to_string(),
        "local deletion acknowledgment absent"
    );
    assert_eq!(operation(&fixture, &key), owned);
    assert!(original.paths[1].exists());
    assert!(original.paths[2].exists());
    if !swallow {
        assert!(original.paths[0].exists());
    }
    fixture.fs.assert_consumed();
    drop(collection);
    fixture.cleanup();
}

#[tokio::test]
async fn unit_success_or_swallowed_sync_failure_never_acknowledges_progress() {
    tokio::join!(missing_ack(false), missing_ack(true));
}
