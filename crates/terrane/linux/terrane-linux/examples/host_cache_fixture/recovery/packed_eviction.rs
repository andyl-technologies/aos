//! Exercises whole-data-pack retirement with real pins and retained descriptions.
//!
//! The independent guest supervisor checks both original native inodes, actual
//! quota and durable funding. Control messages carry no publisher authority.

use super::{Inputs, STATE};
use crate::encoded_eviction::{Observed, control, observe, pressure};
use std::{
    fs,
    io::{self, Write},
    time::UNIX_EPOCH,
};
use terrane_format::identity::{IdentityKind, TERRANE_V1};
use terrane_linux::host_cache::{NativeConsumerLease, NativeMetadataOwner};
use terrane_sdk::{
    host::cache::CacheState,
    store::{Clock, TokioClock, TokioLocalFs},
};

/// Retires exactly the original pair while separate consumers retain other units.
///
/// # Errors
/// Refuses lost original protection, changed native descriptors, incorrect unit
/// retirement, premature reclamation or failure to retain independent consumers.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    consumers: &[NativeConsumerLease],
) -> io::Result<()> {
    let pair = super::encoded::pack_paths(inputs)
        .into_iter()
        .map(|path| Observed::new(fs::File::open(&path)?, fs::read(path)?))
        .collect::<io::Result<Vec<_>>>()?;
    let bytes = pair.iter().try_fold(0_u64, |total, member| {
        total
            .checked_add(member.allocated)
            .ok_or_else(|| invalid("data pack allocation overflow"))
    })?;
    let paths = super::encoded::pack_paths(inputs);
    let identity = TERRANE_V1
        .calculate(IdentityKind::Pack, &fs::read(&paths[1])?)
        .map_err(io::Error::other)?;
    let hash: String = identity
        .digest()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("data pack durable policy absent"))?;
    let deadline = state
        .pins
        .iter()
        .filter(|pin| pin.hash == hash)
        .map(|pin| pin.expires)
        .max()
        .ok_or_else(|| invalid("original data pack grace absent"))?;
    let now = TokioClock
        .now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    if deadline <= now
        || deadline.saturating_sub(now) > inputs.owner_config()?.policy.release_grace.as_secs() + 3
    {
        return Err(invalid(
            "data pack does not retain its original bounded grace",
        ));
    }
    if pressure(owner, runtime, inputs, bytes)?.retired_allocations != 0 {
        return Err(invalid(
            "data pack retired while its genuine consumer grace remained",
        ));
    }
    println!("PACKED_PAIR_GRACE expires={deadline} allocated={bytes}");
    ready("READY original data pack and independent standalone consumers retain actual grace")?;

    control("retire-data-pack")?;
    let report = pressure(owner, runtime, inputs, bytes)?;
    if report.retired_allocations != 1 || report.target_met {
        return Err(invalid(
            "whole data pack did not retire as one charged allocation",
        ));
    }
    for member in &pair {
        member.check(1)?;
    }
    ready("READY original whole data pack retires as one unit with both descriptions retained")?;

    control("close-data-pack-actor")?;
    for member in &pair {
        member.check(0)?;
    }
    drop(pair);
    observe(owner, runtime, "data-pack-held")?;
    ready("READY actor data pack descriptions closed while independent observers retain charge")?;

    control("data-pack-observers-closed")?;
    observe(owner, runtime, "data-pack-closed")?;
    for consumer in consumers {
        drop(consumer.read_verified()?);
    }
    ready("READY independent standalone consumers survive actual whole data pack charge release")?;

    control("finish-data-pack")?;
    for consumer in consumers {
        runtime.block_on(owner.release_consumer_lease(consumer))?;
    }
    ready(
        "PASS actual whole data pack retires as one native pair and preserves independent consumer custody",
    )
}

fn ready(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
