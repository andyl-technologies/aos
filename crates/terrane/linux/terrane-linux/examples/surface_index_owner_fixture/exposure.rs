//! Checks durable index exposure obligations under actual native owner custody.

use super::{
    Result, config,
    repository_fixture::{MAIN, RepositoryFixture},
};
use std::{
    fs,
    future::Future,
    io,
    task::{Context, Poll, Waker},
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::surface::ViewTarget;
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_sdk::{
    host::cache::{CacheState, ExposurePhase},
    repository::RootNodeLimits,
    store::{Clock, TokioClock, TokioLocalFs},
};

pub(super) async fn verify(owner: &NativeMetadataOwner, inputs: &config::Inputs) -> Result<()> {
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    fixture.commit(b"durable index exposure").await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &ViewTarget::Ref(MAIN.parse()?),
            fixture.authority.token(),
            "sdk",
            RootNodeLimits {
                max_entries: 16,
                max_metadata_bytes: 65536,
                max_path_bytes: 4096,
            },
        )
        .await?;
    let mapped = owner.prepare_surface_mapping(selection).await?;
    let key = mapped.key();
    let policy = inputs.root.join("state/cache/records.toml");
    let before = fs::read(&policy)?;
    if owner.retain_surface_exposure(&mapped, 0).await.is_ok() || fs::read(&policy)? != before {
        return Err("expired exposure changed physical policy".into());
    }

    let expires = now()?.checked_add(90).ok_or("exposure deadline overflow")?;
    let lease = owner.retain_surface_exposure(&mapped, expires).await?;
    let state = snapshot(inputs).await?;
    let row = state
        .exposures
        .iter()
        .find(|row| row.id == lease.id())
        .ok_or("durable exposure missing")?;
    if row.commit != hex(&mapped.commit())
        || row.root != hex(&key.root())
        || row.index_version != key.version()
        || row.generation != lease.generation()
        || row.deadline != expires
        || row.phase != ExposurePhase::Active
        || !state
            .leases
            .iter()
            .any(|entry| entry.owner == row.pin_owner() && entry.expires == i64::MAX as u64)
    {
        return Err("exposure acknowledgment differs from original durable index context".into());
    }
    owner.renew_surface_exposure(&lease, expires + 10).await?;
    owner.drain_surface_exposure(&lease).await?;
    owner.drain_surface_exposure(&lease).await?;
    let before = fs::read(&policy)?;
    if owner
        .renew_surface_exposure(&lease, expires + 20)
        .await
        .is_ok()
        || fs::read(&policy)? != before
    {
        return Err("draining exposure was resurrected or changed by refused renewal".into());
    }

    let deadline = now()? + 2;
    let stall = owner.stall_policy_for_fixture().await?;
    let mut abandoned = Box::pin(owner.retain_surface_exposure(&mapped, deadline));
    let mut context = Context::from_waker(Waker::noop());
    if !matches!(abandoned.as_mut().poll(&mut context), Poll::Pending) {
        return Err("exposure cancellation did not enqueue behind actual held policy".into());
    }
    drop(abandoned);
    drop(stall);
    let elapsed = owner.retain_surface_exposure(&mapped, deadline).await?;
    if snapshot(inputs).await?.exposures.len() != 3 {
        return Err("cancelled waiter lost its durable exposure obligation".into());
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if snapshot(inputs)
                .await?
                .exposures
                .iter()
                .all(|row| row.phase == ExposurePhase::Draining)
            {
                return Ok::<(), Box<dyn std::error::Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    drop(mapped);
    drop(lease);
    drop(elapsed);
    let before = fs::read(&policy)?;
    if !matches!(owner.evict_surface_index(key).await, Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        || fs::read(&policy)? != before
        || snapshot(inputs)
            .await?
            .exposures
            .iter()
            .any(|row| row.phase != ExposurePhase::Draining)
    {
        return Err("exposure receipt drop or expiry released original index obligations".into());
    }
    println!(
        "PASS durable root exposure acknowledges original index context; cancellation retains obligations and renewal and expiry drain without releasing custody after receipt drop"
    );
    Ok(())
}

async fn snapshot(inputs: &config::Inputs) -> Result<CacheState> {
    CacheState::load(
        &TokioLocalFs,
        &inputs.root.join("state/cache"),
        config::STATE,
    )
    .await?
    .ok_or_else(|| "durable exposure snapshot missing".into())
}

fn now() -> Result<u64> {
    Ok(TokioClock.now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
