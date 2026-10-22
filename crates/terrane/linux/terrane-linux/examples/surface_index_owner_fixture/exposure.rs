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
use terrane_format::surface::{View, ViewTarget};
use terrane_linux::host_cache::NativeMetadataOwner;
use terrane_sdk::{
    host::cache::{CacheState, ExposurePhase},
    repository::RootNodeLimits,
    store::{Clock, TokioClock, TokioLocalFs},
};

#[path = "exposure/root.rs"]
mod root;

#[path = "exposure/backing.rs"]
mod backing;

#[path = "exposure/census.rs"]
mod census;

#[path = "exposure/closure.rs"]
mod closure;

fn limits() -> RootNodeLimits {
    RootNodeLimits {
        max_entries: 16,
        max_metadata_bytes: 65536,
        max_path_bytes: 4096,
    }
}

pub(super) async fn verify(owner: &NativeMetadataOwner, inputs: &config::Inputs) -> Result<()> {
    let fixture = RepositoryFixture::new(&inputs.domain).await?;
    fixture.commit(b"signed surface source").await?;
    let selection = fixture
        .repository
        .prepare_root_read(
            &ViewTarget::Ref(MAIN.parse()?),
            fixture.authority.token(),
            "sdk",
            limits(),
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
    let target = ViewTarget::Commit(mapped.commit());
    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    let root_grant = owner
        .prepare_exposure_root_backing(&lease, &mapped, selection)
        .await?;
    if root_grant.exposure().id() != lease.id()
        || root_grant.exposure().generation() != lease.generation()
    {
        return Err("root descriptor grant lost the exact original exposure context".into());
    }
    root::check(&root_grant, inputs).await?;
    census::verify(&root_grant, inputs)?;
    let closing_root = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    owner.renew_surface_exposure(&lease, expires + 10).await?;
    let view = View::parse(MAIN)?;
    let draining_selection = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    let (pin_owner, object) = verify_file(owner, &mapped, &lease, &fixture, expires - 1).await?;
    if !matches!(owner.prepare_exposure_root_backing(&lease, &mapped, closing_root).await,
        Err(terrane_sdk::repository::Error::Store(error)) if matches!(error.kind(), terrane_sdk::store::StoreErrorKind::Denied { .. }))
    {
        return Err("root descriptor escaped a changed actual complete-root policy".into());
    }

    let retained_backings = snapshot(inputs).await?.exposures[0].backings.clone();
    owner.drain_surface_exposure(&lease).await?;
    owner.drain_surface_exposure(&lease).await?;
    let selection = fixture
        .repository
        .prepare_root_read(&target, fixture.authority.token(), "sdk", limits())
        .await?;
    if !matches!(owner.prepare_exposure_root_backing(&lease, &mapped, selection).await,
        Err(terrane_sdk::repository::Error::Store(error)) if matches!(error.kind(), terrane_sdk::store::StoreErrorKind::Denied { .. }))
    {
        return Err("draining exposure granted a new index descriptor".into());
    }
    root::check(&root_grant, inputs).await?;
    drop(root_grant);

    let before = fs::read(&policy)?;
    if owner
        .renew_surface_exposure(&lease, expires + 20)
        .await
        .is_ok()
        || fs::read(&policy)? != before
    {
        return Err("draining exposure was resurrected or changed by refused renewal".into());
    }
    let before = snapshot(inputs).await?;
    if !matches!(owner.prepare_exposure_file_backing(&lease, &mapped, draining_selection, expires - 1).await,
        Err(terrane_sdk::repository::Error::Store(error)) if matches!(error.kind(), terrane_sdk::store::StoreErrorKind::Denied { .. }))
    {
        return Err("draining exposure disclosed new file backing".into());
    }
    let after = snapshot(inputs).await?;
    if after
        .leases
        .iter()
        .any(|row| !before.leases.iter().any(|old| old.owner == row.owner))
    {
        return Err("draining exposure accepted a new physical consumer".into());
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
    let state = snapshot(inputs).await?;
    if state.exposures[0].backings != retained_backings
        || retained_backings.len() != 2
        || state.exposures.iter().any(|row| row.backings.is_empty())
    {
        return Err("drain, expiry or receipt drop lost original inode obligations".into());
    }
    if !state
        .pins
        .iter()
        .any(|pin| pin.owner == pin_owner && pin.hash == object && pin.expires == i64::MAX as u64)
    {
        return Err(
            "ordinary release, drain or receipt drop released exposure object protection".into(),
        );
    }
    println!(
        "PASS scoped exposure root grants the original read-only index; changed policy and draining deny new grants while retained metadata remains readable"
    );
    println!(
        "PASS actual sealed exposure file is pinned before closing Read; ordinary release and draining preserve durable object protection"
    );
    println!(
        "PASS durable root exposure acknowledges original index context; cancellation retains obligations and renewal and expiry drain without releasing custody after receipt drop"
    );
    println!(
        "PASS durable exposure records match actual original index and file inodes and verity measurements; draining and receipt drop retain all bindings"
    );
    println!(
        "PASS authenticated census helper retains actual disclosed index custody and refuses an unconfigured owner and domain"
    );
    closure::verify(owner, inputs, &fixture).await?;
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

/// Checks actual file protection and a genuine closing policy-head refusal.
async fn verify_file(
    owner: &NativeMetadataOwner,
    mapped: &terrane_linux::host_cache::NativeRootIndex,
    lease: &terrane_linux::host_cache::NativeExposureLease,
    fixture: &RepositoryFixture,
    expires: u64,
) -> Result<(String, String)> {
    let backing =
        super::scoped::admit_exposure_file(owner, mapped, fixture, lease, expires).await?;
    let pin_owner = format!("exposure:{}", lease.id());
    let object = hex(backing.lease().identity().digest());
    let view = View::parse(MAIN)?;
    let selection = fixture
        .repository
        .prepare_file_read(&view, b"file", fixture.authority.token(), "sdk")
        .await?;
    fixture.commit(b"later exposure policy head").await?;
    if !matches!(owner.prepare_exposure_file_backing(lease, mapped, selection, expires).await,
        Err(terrane_sdk::repository::Error::Store(error)) if matches!(error.kind(), terrane_sdk::store::StoreErrorKind::Denied { .. }))
    {
        return Err("exposure file backing escaped the actual closing Read".into());
    }
    let inputs = config::Inputs::load()?;
    let file = std::fs::File::from(std::os::fd::AsFd::as_fd(&backing).try_clone_to_owned()?);
    backing::check(
        &file,
        lease.id(),
        terrane_sdk::host::cache::ExposureBackingKind::Inline,
        &object,
        &inputs,
    )
    .await?;
    let state = snapshot(&inputs).await?;
    if !state
        .pins
        .iter()
        .any(|pin| pin.owner == pin_owner && pin.hash == object && pin.expires == i64::MAX as u64)
    {
        return Err("original exposure file was disclosed before its durable object pin".into());
    }
    owner.release_sealed_object_lease(backing.lease()).await?;
    drop(backing);
    Ok((pin_owner, object))
}
