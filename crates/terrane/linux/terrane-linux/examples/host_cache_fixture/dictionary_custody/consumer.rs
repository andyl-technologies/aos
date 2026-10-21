//! Verifies independent encoded consumer protection through actual release grace.

use super::{Inputs, invalid, load};
use std::{
    fs, io,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::mpsc,
    thread,
    time::{Duration, UNIX_EPOCH},
};
use terrane_format::identity::Identity;
use terrane_linux::host_cache::{NativeConsumerLease, NativeLeaseAccounting, NativeMetadataOwner};
use terrane_sdk::{
    host::cache::CacheState,
    store::{Clock, TokioClock},
};

/// Grants, reads, renews and releases a real admitted encoded consumer.
///
/// # Errors
/// Refuses missing independent durable pins, incorrect original allocation,
/// serialized reads under stalled policy, changed plaintext or failed revocation.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    identity: Identity,
    plaintext: &[u8],
    dictionary: &Path,
    dependent: &Path,
) -> io::Result<(NativeConsumerLease, NativeLeaseAccounting)> {
    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("encoded lease expiry overflow"))?;
    let lease = runtime.block_on(owner.pin_resident_chunk(identity, expires))?;
    let allocated = [dictionary, dependent]
        .into_iter()
        .try_fold(0_u64, |sum, path| {
            sum.checked_add(
                fs::metadata(path)?
                    .blocks()
                    .checked_mul(512)
                    .ok_or_else(|| invalid("encoded allocation overflow"))?,
            )
            .ok_or_else(|| invalid("encoded allocation overflow"))
        })?;
    if lease.initial_accounting().synchronized_sealed_inode_bytes != 0
        || lease.initial_accounting().synchronized_backing_inode_bytes != allocated
        || lease.initial_accounting().future_hold_bytes != 2 * super::HOLD
        || lease.read_verified()? != plaintext
    {
        return Err(invalid(
            "encoded consumer lacks actual original backing or distinct funding",
        ));
    }
    check_policy(&load(runtime, inputs)?, &lease, expires)?;

    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    let (send, receive) = mpsc::channel();
    let mut threads = Vec::new();
    for _ in 0..2 {
        let lease = lease.clone();
        let send = send.clone();
        threads.push(thread::spawn(move || {
            let _ = send.send(lease.read_verified());
        }));
    }
    drop(send);
    let reads = (0..2)
        .map(|_| receive.recv_timeout(Duration::from_secs(2)))
        .collect::<Vec<_>>();
    // Release the actual writer even if an implementation error blocks a reader.
    drop(stalled);
    for thread in threads {
        thread
            .join()
            .map_err(|_| invalid("encoded reader panicked"))?;
    }
    for read in reads {
        if read.map_err(io::Error::other)?? != plaintext {
            return Err(invalid(
                "concurrent encoded policy-held read changed plaintext",
            ));
        }
    }
    let renewed = expires
        .checked_add(90)
        .ok_or_else(|| invalid("encoded renewal overflow"))?;
    let observation = runtime.block_on(owner.renew_consumer_lease(&lease, renewed))?;
    if lease.expires_at()? != renewed
        || observation.synchronized_backing_inode_bytes != allocated
        || observation.synchronized_sealed_inode_bytes != 0
        || lease.read_verified()? != plaintext
    {
        return Err(invalid(
            "encoded renewal changed backing or failed actual grant",
        ));
    }
    check_policy(&load(runtime, inputs)?, &lease, renewed)?;

    let released = runtime.block_on(owner.release_consumer_lease(&lease))?;
    if lease.read_verified().is_ok()
        || released.synchronized_sealed_inode_bytes != 0
        || released.synchronized_backing_inode_bytes != allocated
        || released.future_hold_bytes != 2 * super::HOLD
    {
        return Err(invalid(
            "encoded release lost native allocation, revocation or grace funding",
        ));
    }
    let policy = load(runtime, inputs)?;
    let grace = lease.owner().replacen("consumer:", "consumer-grace:", 1);
    let deadline = policy
        .leases
        .iter()
        .find(|row| row.owner == grace)
        .ok_or_else(|| invalid("encoded consumer release grace absent"))?
        .expires;
    if policy.pins.iter().filter(|row| row.owner == grace).count() != 2 {
        return Err(invalid(
            "encoded release lost independent body/dictionary pins",
        ));
    }
    super::emit(&format!(
        "ENCODED_CONSUMER_GRACE owner={grace} expires={deadline} backing_inode_bytes={allocated} charged_reserved_bytes={} future_hold_bytes={}",
        released.charged_reserved_bytes, released.future_hold_bytes
    ))?;
    super::emit(
        "PASS genuine encoded consumer reads and renews original body and dictionary concurrently under stalled policy, then revokes with distinct durable release protection",
    )?;
    Ok((lease, released))
}

fn check_policy(policy: &CacheState, lease: &NativeConsumerLease, expires: u64) -> io::Result<()> {
    let pins: Vec<_> = policy
        .pins
        .iter()
        .filter(|pin| pin.owner == lease.owner())
        .collect();
    if pins.len() != 2
        || pins.iter().any(|pin| pin.expires != expires)
        || !policy
            .leases
            .iter()
            .any(|row| row.owner == lease.owner() && row.expires == expires)
        || policy.reservations.len() != 2
    {
        return Err(invalid(
            "encoded consumer lacks its independent synchronized protection set",
        ));
    }
    Ok(())
}

/// Refuses a fresh grant after a same-bytes rewrite changes the original stamp.
///
/// # Errors
/// Refuses an unchanged timestamp, different bytes/inode, a grant accepted from
/// changed original metadata, policy mutation on refusal or unusable custody.
pub(super) fn reject_rewritten(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    identity: Identity,
    path: &Path,
    encoded: &[u8],
) -> io::Result<()> {
    use std::io::Write;

    let policy = inputs.root.join("state/cache/records.toml");
    let original_policy = fs::read(&policy)?;
    let mut writer = fs::OpenOptions::new().write(true).open(path)?;
    let before = writer.metadata()?;
    writer.write_all(encoded)?;
    writer.sync_all()?;
    let after = writer.metadata()?;
    drop(writer);
    if (before.dev(), before.ino(), before.len()) != (after.dev(), after.ino(), after.len())
        || (
            before.ctime(),
            before.ctime_nsec(),
            before.mtime(),
            before.mtime_nsec(),
        ) == (
            after.ctime(),
            after.ctime_nsec(),
            after.mtime(),
            after.mtime_nsec(),
        )
        || fs::read(path)? != encoded
    {
        return Err(invalid(
            "same-bytes rewrite did not change only original admission metadata",
        ));
    }

    let expires = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs()
        .checked_add(90)
        .ok_or_else(|| invalid("rewritten source deadline overflow"))?;
    let error = runtime
        .block_on(owner.pin_resident_chunk(identity, expires))
        .err()
        .ok_or_else(|| invalid("rewritten original admission received a fresh grant"))?;
    if error.to_string() != "retained admission file metadata changed"
        || fs::read(policy)? != original_policy
    {
        return Err(io::Error::other(format!(
            "rewritten admission refused outside its original stamp check or changed policy: {error:?}"
        )));
    }
    super::emit(
        "PASS actual same-bytes rewrite retains original inode and plaintext but refuses a fresh encoded grant at the original admission stamp without policy mutation",
    )?;
    super::control("quarantine")?;
    if runtime.block_on(owner.sweep_consumer_leases()).is_ok() {
        return Err(invalid("rewritten source did not fault its original owner"));
    }
    super::emit(
        "READY rewritten encoded original quarantined with dictionary dependency and funding retained",
    )?;
    super::control("quarantine-checked")
}
