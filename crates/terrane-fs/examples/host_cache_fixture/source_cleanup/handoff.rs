//! Exercises actual producer funding release and fresh cached consumer grants.

use super::{Inputs, control, emit, invalid};
use std::{
    collections::BTreeSet,
    future::Future,
    io,
    task::{Context, Poll, Waker},
};
use terrane::{host::cache::CacheState, store::TokioLocalFs};
use terrane_fs::host_cache::{
    NativeCacheHandoffError, NativeConsumerLease, NativeInlinePublication,
    NativeManifestPublication, NativeMetadataOwner,
};

/// Consumes actual publications after native cleanup while retaining live consumers.
///
/// # Errors
/// Refuses changed accounting, metadata protection, grants or native backing.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    inline: NativeInlinePublication,
    manifest: NativeManifestPublication,
    consumer: &NativeConsumerLease,
    expected: &[u8],
) -> io::Result<()> {
    control("handoff")?;
    let inline = refuse_full_queue(owner, runtime, inputs, inline)?;
    let before = load(runtime, inputs)?;
    let mut hashes = BTreeSet::new();
    hashes.insert(hex(inline.claim().descriptor().digest()));
    for chunk in &manifest
        .claim()
        .manifest()
        .ok_or_else(|| invalid("handoff manifest absent"))?
        .chunks
    {
        hashes.insert(hex(&chunk.digest));
    }
    let mut removed: BTreeSet<String> = before
        .leases
        .iter()
        .filter_map(|lease| lease.owner.strip_prefix("publication:").map(str::to_owned))
        .collect();
    for pin in &before.pins {
        if hashes.contains(&pin.hash)
            && let Some(token) = pin.owner.strip_prefix("admission:")
        {
            removed.insert(token.to_owned());
        }
    }
    if removed.len() != 5 {
        return Err(invalid(
            "handoff lacks two original producers and three source admissions",
        ));
    }
    let released = before
        .reservations
        .iter()
        .filter(|hold| removed.contains(&hold.id))
        .try_fold(0_u64, |sum, hold| {
            sum.checked_add(hold.bytes)
                .ok_or_else(|| invalid("handoff hold sum overflow"))
        })?;
    let expected_future = future(&before)?
        .checked_sub(released)
        .ok_or_else(|| invalid("handoff released hold exceeds original policy"))?;
    let inline = runtime
        .block_on(inline.into_cache(owner))
        .map_err(io::Error::other)?;
    let manifest = runtime
        .block_on(manifest.into_cache(owner))
        .map_err(io::Error::other)?;
    let policy_stall = runtime.block_on(owner.stall_policy_for_fixture())?;
    let after = load(runtime, inputs)?;
    if inline.released_source_admissions != 1
        || manifest.released_source_admissions != 2
        || manifest.future_hold_bytes != expected_future
        || future(&after)? != expected_future
        || after
            .reservations
            .iter()
            .any(|hold| removed.contains(&hold.id))
        || after.leases.iter().any(|lease| {
            lease.owner.starts_with("publication:")
                || lease
                    .owner
                    .strip_prefix("admission:")
                    .is_some_and(|token| removed.contains(token))
        })
        || after.pins.iter().any(|pin| {
            pin.owner.starts_with("publication:")
                || pin
                    .owner
                    .strip_prefix("admission:")
                    .is_some_and(|token| removed.contains(token))
        })
    {
        return Err(invalid(
            "cache handoff retained obsolete funding or changed unrelated holds",
        ));
    }
    for pin in before
        .pins
        .iter()
        .filter(|pin| pin.owner.starts_with("metadata:"))
    {
        if !after.pins.iter().any(|current| {
            current.owner == pin.owner && current.hash == pin.hash && current.expires == pin.expires
        }) {
            return Err(invalid("cache handoff released reconstruction metadata"));
        }
    }
    drop(policy_stall);
    let fresh = runtime
        .block_on(owner.pin_resident_chunk(consumer.identity().clone(), consumer.expires_at()?))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    if consumer.read_verified()? != expected || fresh.read_verified()? != expected {
        return Err(invalid(
            "cache handoff invalidated an old or fresh consumer grant",
        ));
    }
    drop(stalled);
    emit(&format!(
        "CACHE_HANDOFF_GRACE expires={} released_future_hold_bytes={}",
        inline
            .release_grace_ends_at
            .max(manifest.release_grace_ends_at),
        released
    ))?;
    emit("READY actual cache handoff retains independent consumers and reconstruction metadata")?;
    control("after-grace")?;
    let expired = load(runtime, inputs)?;
    if expired
        .leases
        .iter()
        .any(|lease| lease.owner.starts_with("publication-grace:"))
        || expired
            .pins
            .iter()
            .any(|pin| pin.owner.starts_with("publication-grace:"))
    {
        return Err(invalid(
            "periodic sweep retained expired cache handoff grace",
        ));
    }
    // Renewal exercises the cached source after producer funding and grace
    // have both gone, then gives the controller a stable fresh quota witness.
    let deadline = fresh
        .expires_at()?
        .checked_add(10)
        .ok_or_else(|| invalid("cached consumer deadline overflow"))?;
    let observed = runtime.block_on(owner.renew_consumer_lease(&fresh, deadline))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    if consumer.read_verified()? != expected || fresh.read_verified()? != expected {
        return Err(invalid(
            "expired producer grace invalidated independent consumer reads",
        ));
    }
    drop(stalled);
    emit(&format!(
        "CACHE_HANDOFF_MEASUREMENT charged_reserved_bytes={} future_hold_bytes={}",
        observed.charged_reserved_bytes, observed.future_hold_bytes
    ))?;
    emit("READY actual cache handoff grace expired with original owner and consumers retained")?;
    control("finish")?;
    emit(
        "PASS actual cache handoff releases producer and closed-source funding, retains reconstruction metadata, and grants fresh consumer reads after durable grace; no Ready",
    )?;
    super::eviction::run(owner, runtime, inputs, consumer, &fresh, expected)
}

fn refuse_full_queue(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    publication: NativeInlinePublication,
) -> io::Result<NativeInlinePublication> {
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let before = std::fs::read(super::policy(inputs))?;
    let mut queued = Vec::new();
    for _ in 0..inputs.owner_config()?.queued_commands {
        let mut sweep = Box::pin(owner.sweep_consumer_leases());
        if !matches!(
            sweep.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return Err(invalid("stalled physical owner completed a queued sweep"));
        }
        queued.push(sweep);
    }

    let mut attempt = Box::pin(publication.into_cache(owner));
    let recovered = match attempt
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(Err(NativeCacheHandoffError::Unsubmitted { error, publication }))
            if error.kind() == io::ErrorKind::WouldBlock =>
        {
            publication
        }
        _ => {
            return Err(invalid(
                "full handoff queue lost the original retry receipt",
            ));
        }
    };
    drop(attempt);
    if std::fs::read(super::policy(inputs))? != before {
        return Err(invalid("unsubmitted cache handoff changed durable policy"));
    }
    drop(stalled);
    for sweep in queued {
        if runtime.block_on(sweep)? != 0 {
            return Err(invalid(
                "queue refusal control unexpectedly expired a lease",
            ));
        }
    }
    emit(
        "PASS full cache handoff queue returns the original publication for retry without policy mutation",
    )?;
    Ok(recovered)
}

fn load(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            super::super::config::STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("cache handoff policy absent"))
}

fn future(state: &CacheState) -> io::Result<u64> {
    state.reservations.iter().try_fold(0_u64, |sum, hold| {
        sum.checked_add(hold.bytes)
            .ok_or_else(|| invalid("cached future hold sum overflow"))
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
