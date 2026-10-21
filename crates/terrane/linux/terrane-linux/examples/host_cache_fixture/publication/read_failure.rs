//! Exercises real failed sealed custody with policy held and the owner queue full.

use super::{
    Inputs, NativeMetadataOwner, PLAINTEXT, STATE, control, descriptor, emit, encoded, invalid,
};
use std::{
    fs,
    future::Future,
    io,
    os::unix::fs::MetadataExt,
    task::{Context, Poll, Waker},
    time::UNIX_EPOCH,
};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_sdk::store::{Clock, TokioClock};

pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    let published = runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, PLAINTEXT)
        .map_err(io::Error::other)?;
    let first = runtime.block_on(owner.retain_resident_chunk(identity.clone()))?;
    let alias = runtime.block_on(owner.retain_resident_chunk(identity.clone()))?;
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(30)
        .ok_or_else(|| invalid("failure fixture expiry overflow"))?;
    let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
    if first.read_verified()? != PLAINTEXT
        || alias.read_verified()? != PLAINTEXT
        || lease.read_verified()? != PLAINTEXT
    {
        return Err(invalid("failure fixture lacked original verified readers"));
    }
    let before = published.handle().metadata()?;
    let policy = inputs.root.join("state/cache/records.toml");
    let records = fs::read(&policy)?;
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let mut queued = Vec::new();
    let mut saturated = false;
    for _ in 0..=STATE.records {
        let mut pending = Box::pin(owner.sweep_consumer_leases());
        match pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Pending => queued.push(pending),
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                saturated = true;
                break;
            }
            _ => {
                return Err(invalid(
                    "stalled owner unexpectedly completed a queued command",
                ));
            }
        }
    }
    if !saturated || queued.is_empty() {
        return Err(invalid(
            "failure fixture did not fill the genuine finite queue",
        ));
    }
    emit("READY original sealed readers verified with policy held and genuine owner queue full")?;
    control("damaged")?;
    if first.read_verified().is_ok() || fs::read(&policy)? != records {
        return Err(invalid(
            "changed native custody was served or changed durable funding",
        ));
    }
    emit("READY actual sealed custody failure latched while policy and full queue remain held")?;
    control("restored")?;
    if published.handle().metadata()?.mode() & 0o7777 != 0o400
        || alias.read_verified().is_ok()
        || lease.read_verified().is_ok()
        || lease.read_encoded().is_ok()
    {
        return Err(invalid(
            "restoring inode mode revived a rejected reader alias",
        ));
    }
    // Drop every later reply waiter; the retained failure report uses no queue
    // slot and must be processed before this first accepted command resumes.
    let barrier = queued.remove(0);
    drop(queued);
    drop(stalled);
    if runtime.block_on(barrier).is_ok() || fs::read(&policy)? != records {
        return Err(invalid(
            "failed-read quarantine released original durable protection",
        ));
    }
    let after = published.handle().metadata()?;
    if (after.dev(), after.ino(), after.nlink(), after.blocks())
        != (before.dev(), before.ino(), 1, before.blocks())
    {
        return Err(invalid(
            "failed-read quarantine lost original inode allocation",
        ));
    }
    emit(
        "READY physical failed-read quarantine completed with original inode and durable protection retained",
    )?;
    control("finish")?;
    emit(
        "PASS actual sealed read failure survives full queue and cancelled waiters, denies original producer and consumer aliases, and quarantines original inode without funding release",
    )
}
