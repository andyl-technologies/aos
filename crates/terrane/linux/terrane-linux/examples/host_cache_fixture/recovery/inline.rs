//! Checks real recovered inline source pins and dropped native command waiters.
//!
//! The supervisor stops the actual quota helper. An original manifest source
//! remains readable while the new physical source-pin command cannot finish.
//! No fixture constructs an adopted handle, source receipt or synchronized pin.

use super::*;
use std::{
    future::Future,
    io::BufRead,
    task::{Context, Poll, Waker},
};
use terrane_format::identity::Identity;

fn identity() -> io::Result<Identity> {
    TERRANE_V1
        .calculate(IdentityKind::Chunk, INLINE_BYTES)
        .map_err(io::Error::other)
}

/// Refuses an actually adopted inline candidate before complete recovery and Resume.
///
/// # Errors
/// Refuses a premature source acknowledgment or any changed durable policy.
pub(super) fn refuse(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    if runtime
        .block_on(owner.retain_resident_chunk(identity()?))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
    {
        return Err(invalid(
            "adopted inline candidate gained a pin before complete recovery and Resume",
        ));
    }
    emit(
        "PASS actual adopted inline source refused before complete recovery and Resume; policy unchanged",
    )
}

/// Drops an accepted actual source waiter while retaining original native pin custody.
///
/// # Errors
/// Refuses a nonpending stopped-helper operation, a stalled original source
/// read, duplicate source funding, lost native backing or changed residences.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let fixture = Fixture::new()?;
    let range = ChunkProfile::cdc_1m([0; 32])
        .ranges(&fixture.plaintext)
        .next()
        .ok_or_else(|| invalid("mixed fixture lacks an actual original source"))?;
    let old_bytes = &fixture.plaintext[range];
    let old_identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, old_bytes)
        .map_err(io::Error::other)?;
    let old_source = runtime.block_on(owner.retain_resident_chunk(old_identity))?;
    let initial = fs::read(inputs.root.join("state/cache/records.toml"))?;
    emit("READY actual mixed recovery and old source retained; wait for inline pin control")?;
    control("pin")?;
    let mut pending = Box::pin(owner.retain_resident_chunk(identity()?));
    if !matches!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return Err(invalid(
            "stopped quota helper did not retain the actual inline pin waiter",
        ));
    }
    drop(pending);
    if old_source.read_verified()? != old_bytes {
        return Err(invalid(
            "blocked inline pin changed the actual original manifest source",
        ));
    }
    emit(
        "CANCELLED accepted inline source waiter; original sealed source read while quota helper stopped",
    )?;
    control("resumed")?;

    let source = runtime.block_on(owner.retain_resident_chunk(identity()?))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let actual = source.read_verified()?;
    drop(stalled);
    if actual != INLINE_BYTES
        || source.span().offset != 0
        || source.span().length != INLINE_BYTES.len()
        || !source.span().final_chunk
    {
        return Err(invalid(
            "recovered inline source differs from original adopted bytes",
        ));
    }
    let pinned = fs::read(inputs.root.join("state/cache/records.toml"))?;
    let repeated = runtime.block_on(owner.retain_resident_chunk(identity()?))?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let repeated_bytes = repeated.read_verified()?;
    drop(stalled);
    if initial == pinned
        || repeated_bytes != INLINE_BYTES
        || fs::read(inputs.root.join("state/cache/records.toml"))? != pinned
    {
        return Err(invalid(
            "recovered inline source lost its unique durable pin or funded again",
        ));
    }
    emit(
        "PASS actual recovered inline source retained its durable pin after a dropped waiter and read with policy held; repeated preparation preserved the original hold; no Ready",
    )?;
    emit("READY original recovered inline pin checked; wait for assembly control")?;
    control("assemble")?;
    super::reuse::run_inline(owner, runtime, inputs)
}

fn emit(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != expected {
        return Err(invalid("unexpected recovered inline native control"));
    }
    Ok(())
}
