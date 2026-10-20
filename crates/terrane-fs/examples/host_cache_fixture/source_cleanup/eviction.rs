//! Exercises real cached-body rename, pin restoration, grace and final unlink.

use super::{Inputs, control, emit, invalid};
use std::{
    future::Future,
    io,
    task::{Context, Poll, Waker},
};
use terrane::{host::cache::CacheState, store::TokioLocalFs};
use terrane_core::identity::{IdentityKind, TERRANE_V1};
use terrane_fs::host_cache::{NativeCacheEvictionReport, NativeConsumerLease, NativeMetadataOwner};

/// Keeps the original Running owner and independent consumers through eviction.
///
/// # Errors
/// Refuses lost canonical custody, premature grace removal, false reclamation
/// reports or invalid independent consumer reads.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    consumer: &NativeConsumerLease,
    fresh: &NativeConsumerLease,
    expected: &[u8],
) -> io::Result<()> {
    control("evict")?;
    for lease in [consumer, fresh] {
        let expires = lease
            .expires_at()?
            .checked_add(240)
            .ok_or_else(|| invalid("eviction consumer deadline overflow"))?;
        runtime.block_on(owner.renew_consumer_lease(lease, expires))?;
    }
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, super::INLINE)
        .map_err(io::Error::other)?;
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    emit(&format!("CACHE_EVICTION_TARGET hash={hash}"))?;
    emit("READY native eviction controls retain extended independent consumers")?;
    control("retire")?;
    let retired = pressure(owner, runtime, inputs)?;
    if retired.retired_allocations != 1 || retired.target_met {
        return Err(invalid(
            "pending inline retirement inferred freed allocation",
        ));
    }
    emit(&format!(
        "CACHE_EVICTION_PENDING phase=initial charged_reserved_bytes={} future_hold_bytes={}",
        retired.charged_reserved_bytes, retired.future_hold_bytes
    ))?;
    emit("READY actual cached inline pending retirement with charge retained")?;

    control("repin")?;
    let blocked = runtime.block_on(owner.stall_policy_for_fixture())?;
    let mut request = Box::pin(owner.pin_resident_chunk(identity.clone(), consumer.expires_at()?));
    if !matches!(
        request
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return Err(invalid(
            "stalled physical owner acknowledged inline pin before restoration",
        ));
    }
    emit("READY inline pin accepted before deadline while original physical owner is stalled")?;
    control("release-stall")?;
    drop(blocked);
    let pinned = runtime.block_on(request)?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    if pinned.read_verified()? != super::INLINE
        || consumer.read_verified()? != expected
        || fresh.read_verified()? != expected
    {
        return Err(invalid(
            "pending cache restoration lost original inline or independent consumers",
        ));
    }
    drop(stalled);
    emit("READY actual inline consumer pin restores canonical backing and reads with policy held")?;

    control("release-pin")?;
    runtime.block_on(owner.release_consumer_lease(&pinned))?;
    if pinned
        .read_verified()
        .err()
        .is_none_or(|error| error.kind() != io::ErrorKind::PermissionDenied)
    {
        return Err(invalid("released inline consumer retained read access"));
    }
    let protected = pressure(owner, runtime, inputs)?;
    if protected.retired_allocations != 0 || protected.target_met {
        return Err(invalid("S3 FIFO evicted a pin protected by release grace"));
    }
    let policy = load(runtime, inputs)?;
    let pins: Vec<_> = policy
        .pins
        .iter()
        .filter(|pin| pin.hash == hash && pin.owner.starts_with("consumer-grace:"))
        .collect();
    let [pin] = pins.as_slice() else {
        return Err(invalid(
            "inline release lacks its original durable grace pin",
        ));
    };
    if !policy
        .leases
        .iter()
        .any(|lease| lease.owner == pin.owner && lease.expires == pin.expires)
    {
        return Err(invalid("inline release grace changed original lease"));
    }
    emit(&format!("CACHE_EVICTION_PIN_GRACE expires={}", pin.expires))?;
    emit("READY released inline pin prevents eviction through its durable grace")?;

    control("retire-after-grace")?;
    let retired = pressure(owner, runtime, inputs)?;
    if retired.retired_allocations != 1 || retired.target_met {
        return Err(invalid(
            "actual post-grace inline retirement lost measured charge",
        ));
    }
    emit(&format!(
        "CACHE_EVICTION_PENDING phase=final charged_reserved_bytes={} future_hold_bytes={}",
        retired.charged_reserved_bytes, retired.future_hold_bytes
    ))?;
    emit("READY actual cached inline pending final removal after release grace")?;

    control("after-delete")?;
    let completed = runtime.block_on(owner.evict_cached(0))?;
    if !completed.target_met
        || runtime
            .block_on(owner.pin_resident_chunk(identity, consumer.expires_at()?))
            .is_ok()
    {
        return Err(invalid(
            "finally removed inline body regained native source authority",
        ));
    }
    emit("READY actual cached inline final removal reconciled with original owner retained")?;
    control("measure-after-observer")?;
    let observed = runtime.block_on(owner.evict_cached(0))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    if consumer.read_verified()? != expected || fresh.read_verified()? != expected {
        return Err(invalid(
            "actual inline eviction invalidated unrelated consumer backing",
        ));
    }
    drop(stalled);
    emit(&format!(
        "CACHE_EVICTION_FINAL charged_reserved_bytes={} future_hold_bytes={}",
        observed.charged_reserved_bytes, observed.future_hold_bytes
    ))?;
    emit(
        "READY independent consumers survive actual final cache retirement and descriptor closure",
    )?;
    control("done")?;
    emit(
        "PASS actual S3 FIFO inline retirement restores for a new pin, preserves release grace, and finally removes original backing before measured quota release; independent consumers remain live; no Ready",
    )
}

fn pressure(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<NativeCacheEvictionReport> {
    let observed = runtime.block_on(owner.evict_cached(0))?;
    let total = observed
        .charged_reserved_bytes
        .checked_add(observed.future_hold_bytes)
        .ok_or_else(|| invalid("native pressure observation overflows"))?;
    let incoming = inputs
        .owner_config()?
        .policy
        .capacity
        .checked_sub(total)
        .and_then(|free| free.checked_add(1))
        .ok_or_else(|| invalid("native cache already exceeds configured capacity"))?;
    runtime.block_on(owner.evict_cached(incoming))
}

fn load(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            super::super::config::STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("eviction policy absent"))
}
