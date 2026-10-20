//! Holds actual native restore workers while mutating their retained inputs.

use super::*;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

/// Proves submitted pair and final publication workers recheck actual continuity.
///
/// # Panics
/// Panics if a real handoff is not reached, consumed or refuses the mutation.
pub(super) async fn changes_refuse() {
    for changed in 0..4 {
        let fixture = Fixture::new().await;
        let (mut collection, id, trash) = retired(&fixture).await;
        let before = image(&fixture).await;
        let path = fixture.config.root.join(id.pack_key());
        let (arrival, release) = fixture.fs.pause_current_pair(path, true);
        let waiter = tokio::task::spawn_blocking(move || {
            arrival.recv_timeout(Duration::from_secs(10)).unwrap()
        });
        let mut operation = Box::pin(collection.restore_pack(selector(&trash)));
        tokio::select! {
            result = &mut operation => panic!("restore ended before native pair handoff: {}", result.is_ok()),
            result = waiter => result.unwrap(),
        }
        let path = match changed {
            0 | 1 => fixture.config.root.join(id.index_key()),
            2 => journal(&fixture, &id.pack_key()),
            3 => fixture.config.root.join(id.pack_key()),
            _ => unreachable!(),
        };
        if changed == 0 || changed == 2 {
            let bytes = tokio::fs::read(&path).await.unwrap();
            let replacement = fixture.parent.join("same-bytes-replacement");
            tokio::fs::write(&replacement, bytes).await.unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
            tokio::fs::rename(replacement, path).await.unwrap();
        } else if changed == 1 {
            let mut bytes = tokio::fs::read(&path).await.unwrap();
            bytes[0] ^= 1;
            tokio::fs::write(path, bytes).await.unwrap();
        } else {
            // Metadata-only refusal; the armed data-body trap stays untouched.
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        release.send(()).unwrap();
        assert!(operation.await.is_err());
        fixture.fs.assert_current_pair_hook_consumed();
        let after = image(&fixture).await;
        assert_eq!(after.cap, before.cap);
        assert_eq!(after.manifest, before.manifest);
        assert_eq!(fixture.fs.data_body_read_attempts(), 0);
    }
    current_control_refuses().await;

    let fixture = Fixture::new().await;
    let (mut collection, _id, trash) = retired(&fixture).await;
    let before = image(&fixture).await;
    let (arrival, release) = fixture
        .fs
        .pause_retirement_barrier(fixture.next_checkpoint_slot().await);
    let waiter =
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.restore_pack(selector(&trash)));
    tokio::select! {
        result = &mut operation => panic!("restore ended before final directory handoff: {}", result.is_ok()),
        result = waiter => result.unwrap(),
    }
    let lease = terrane_format::gc::GcLease::decode(before.logical["gc/lease"].as_deref().unwrap())
        .unwrap();
    fixture.clock.set(lease.expiry + 1_000, lease.expiry + 900);
    release.send(()).unwrap();
    let error = operation.await.unwrap_err();
    assert!(matches!(
        failure_kind(&error),
        StoreErrorKind::Denied { .. }
    ));
    fixture.fs.assert_retirement_hook_consumed();
}

/// Rechecks consumed Original control after the actual final durability handoff.
async fn current_control_refuses() {
    let fixture = Fixture::new().await;
    let (mut collection, id, trash) = retired(&fixture).await;
    let before = image(&fixture).await;
    let changed = fixture.authority.control().join("registration.cbor");
    let original = std::fs::read(&changed).unwrap();
    let (arrival, release) = fixture
        .fs
        .pause_retirement_barrier(fixture.next_checkpoint_slot().await);
    let waiter =
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.restore_pack(selector(&trash)));
    tokio::select! {
        result = &mut operation => panic!("restore ended before live-control handoff: {}", result.is_ok()),
        result = waiter => result.unwrap(),
    }

    let lease = terrane_format::gc::GcLease::decode(before.logical["gc/lease"].as_deref().unwrap())
        .unwrap();
    let clock = fixture.clock.retain_native_clock().unwrap();
    assert!(
        crate::store::Clock::now(&clock)
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            < lease.expiry
    );
    let mut altered = original.clone();
    let last = altered.len() - 1;
    altered[last] ^= 1;
    std::fs::write(&changed, altered).unwrap();
    release.send(()).unwrap();
    let error = operation.await.unwrap_err();
    assert!(matches!(error, CollectionError::Store(_)));
    fixture.fs.assert_retirement_hook_consumed();
    assert!(
        crate::store::Clock::now(&clock)
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            < lease.expiry
    );
    assert!(collection.restore_pack(selector(&trash)).await.is_err());
    std::fs::write(&changed, original).unwrap();

    // Selection may already be physically visible at this final handoff. No
    // completed durable acknowledgment is returned after the control changed.
    let after = image(&fixture).await;
    assert_eq!(after.state.binding, before.state.binding);
    assert_eq!(after.state.guard, before.state.guard);
    assert_eq!(after.state.branches, before.state.branches);
    assert_eq!(after.state.sources, before.state.sources);
    assert_eq!(after.state.loss_generation, before.state.loss_generation);
    assert_eq!(after.state.burn_owners, before.state.burn_owners);
    assert_eq!(after.manifest.inventory, before.manifest.inventory);
    assert_eq!(after.manifest.burns, before.manifest.burns);
    assert!(fixture.config.root.join(id.pack_key()).exists());
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}

/// Proves cancellation retains actual exclusions until the native worker returns.
///
/// # Panics
/// Panics if the actual worker, competing lock or poisoned-session refusal differs.
pub(super) async fn cancellation_refuses() {
    let fixture = Fixture::new().await;
    let (mut collection, id, trash) = retired(&fixture).await;
    let (arrival, release) = fixture
        .fs
        .pause_retirement_barrier(fixture.next_checkpoint_slot().await);
    let waiter =
        tokio::task::spawn_blocking(move || arrival.recv_timeout(Duration::from_secs(10)).unwrap());
    let mut operation = Box::pin(collection.restore_pack(selector(&trash)));
    tokio::select! {
        result = &mut operation => panic!("restore ended before held worker: {}", result.is_ok()),
        result = waiter => result.unwrap(),
    }
    drop(operation);
    let lock = fixture
        .config
        .root
        .join(BucketKey::parse("CAPABILITIES").unwrap().lock_name());
    let contender = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock)
        .unwrap();
    assert!(matches!(
        contender.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    release.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(move || {
            contender.lock().unwrap();
            contender.unlock().unwrap();
        }),
    )
    .await
    .unwrap()
    .unwrap();
    fixture.fs.assert_retirement_hook_consumed();
    assert!(collection.restore_pack(selector(&trash)).await.is_err());
    assert!(fixture.config.root.join(id.pack_key()).exists());
    assert!(fixture.config.root.join(id.index_key()).exists());
    assert_eq!(fixture.fs.data_body_read_attempts(), 0);
}
