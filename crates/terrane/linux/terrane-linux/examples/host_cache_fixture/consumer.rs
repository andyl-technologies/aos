//! Exercises durable consumer grants over original fs-verity backing in a real VM.
//!
//! Both physical owners require genuine confinement, native preparation, recovery
//! and acknowledged Resume. Caller metadata and fixture bytes confer no authority.

mod shared;

use super::config::{HARD_LIMIT, HOLD, Inputs, STATE};
use std::{
    fs,
    future::Future,
    io::{self, BufRead, Write},
    os::unix::fs::MetadataExt,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime},
};
use terrane_format::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_linux::{
    host_cache::{NativeCachePreparation, NativeConsumerLease, NativeMetadataOwner},
    quota_confinement,
};
use terrane_sdk::{
    host::cache::CacheState,
    store::{Clock, TokioClock, TokioLocalFs},
};

const PLAINTEXT: &[u8] = b"actual consumer lease retains original immutable backing";

/// Runs native lease mutations and verifies their actual durable and read effects.
///
/// # Errors
/// Refuses missing native custody, premature acknowledgments or failed controls.
pub(super) fn run(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    confinement: Arc<quota_confinement::Installed>,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:consumer-leases" || original.is_some() {
        return Err(invalid(
            "consumer witness requires its fresh dedicated domain",
        ));
    }
    let completed = runtime.block_on(owner.recover())?;
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, PLAINTEXT)
        .map_err(io::Error::other)?;
    let descriptor =
        Descriptor::from_identity(&TERRANE_V1, &identity, PLAINTEXT).map_err(io::Error::other)?;
    let mut encoded = vec![0];
    encoded.extend_from_slice(PLAINTEXT);
    let published = runtime
        .block_on(owner.publish_inline(descriptor, encoded))
        .map_err(io::Error::other)?;
    let original_inode = published.handle().metadata()?.ino();
    let baseline = load(runtime, inputs)?;
    let baseline_bytes = fs::read(policy_path(inputs))?;
    let expires = now()?
        .checked_add(90)
        .ok_or_else(|| invalid("clock overflow"))?;
    let lease = runtime.block_on(owner.pin_resident_chunk(identity.clone(), expires))?;
    check_read(&lease)?;
    let shared_policy = fs::read(policy_path(inputs))?;
    let shared = shared::SharedChecks::open(runtime, inputs, &lease)?;
    if fs::read(policy_path(inputs))? != shared_policy {
        return Err(invalid(
            "shared directory construction changed durable policy",
        ));
    }
    let pinned = load(runtime, inputs)?;
    check_delta(&baseline, &pinned, &lease, inputs, expires, 1)?;
    let accounting = lease.initial_accounting();
    if accounting.synchronized_sealed_inode_bytes != published.synchronized_sealed_inode_bytes()
        || accounting.charged_reserved_bytes > HARD_LIMIT
        || accounting.future_hold_bytes != published.future_hold_bytes() + HOLD
        || baseline_bytes == fs::read(policy_path(inputs))?
    {
        return Err(invalid(
            "acknowledged consumer pin lacks native allocation and durable hold",
        ));
    }
    let stalled = runtime.block_on(owner.stall_policy_for_fixture())?;
    check_read(&lease)?;
    shared.read(runtime, &lease)?;
    drop(stalled);
    foreign_control(&lease, runtime, inputs, confinement)?;
    emit(&format!(
        "READY consumer lease {} {} {}; actual pin and policy-held read checked",
        lease.owner(),
        expires,
        original_inode
    ))?;
    control("renew")?;
    let renewed = expires
        .checked_add(90)
        .ok_or_else(|| invalid("renewal overflow"))?;
    let mut pending = Box::pin(owner.renew_consumer_lease(&lease, renewed));
    if !matches!(
        pending
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ) {
        return Err(invalid(
            "stopped quota helper did not retain pending renewal",
        ));
    }
    check_read(&lease)?;
    shared.read(runtime, &lease)?;
    if lease.expires_at()? != expires {
        return Err(invalid("pending renewal published its new deadline early"));
    }
    drop(pending);
    emit("CANCELLED consumer renewal waiter; original grant read while quota helper stopped")?;
    control("completed")?;
    // Serialized behind the accepted mutation; this barrier cannot renew a pin.
    runtime.block_on(owner.sweep_consumer_leases())?;
    if lease.expires_at()? != renewed {
        return Err(invalid(
            "dropped renewal waiter cancelled physical completion",
        ));
    }
    check_read(&lease)?;
    check_delta(
        &baseline,
        &load(runtime, inputs)?,
        &lease,
        inputs,
        renewed,
        1,
    )?;
    let released = runtime.block_on(owner.release_consumer_lease(&lease))?;
    shared.revoked(runtime, &lease)?;
    if lease.read_verified().is_ok() || released.future_hold_bytes != accounting.future_hold_bytes {
        return Err(invalid(
            "release failed revocation or discarded grace funding",
        ));
    }
    let released_bytes = fs::read(policy_path(inputs))?;
    let repeated = runtime.block_on(owner.release_consumer_lease(&lease))?;
    if fs::read(policy_path(inputs))? != released_bytes
        || repeated.future_hold_bytes != released.future_hold_bytes
        || repeated.charged_reserved_bytes != released.charged_reserved_bytes
        || repeated.synchronized_sealed_inode_bytes != released.synchronized_sealed_inode_bytes
        || runtime
            .block_on(owner.renew_consumer_lease(&lease, renewed + 1))
            .is_ok()
    {
        return Err(invalid(
            "released lease was renewed or repeated release changed durable policy",
        ));
    }
    let short_expiry = now()?
        .checked_add(3)
        .ok_or_else(|| invalid("expiry overflow"))?;
    let repinned = runtime.block_on(owner.pin_resident_chunk(identity, short_expiry))?;
    check_read(&repinned)?;
    if repinned.owner() == lease.owner()
        || repinned
            .initial_accounting()
            .synchronized_sealed_inode_bytes
            != accounting.synchronized_sealed_inode_bytes
        || published.handle().metadata()?.ino() != original_inode
    {
        return Err(invalid(
            "re-pin duplicated backing or reused a revoked lease",
        ));
    }
    let with_grace = load(runtime, inputs)?;
    let grace_owner = format!(
        "consumer-grace:{}",
        lease.owner().trim_start_matches("consumer:")
    );
    let grace = with_grace
        .leases
        .iter()
        .find(|row| row.owner == grace_owner)
        .ok_or_else(|| invalid("release grace was not persisted"))?
        .expires;
    if grace <= now()?
        || with_grace.reservations.len() != baseline.reservations.len() + 2
        || !with_grace
            .pins
            .iter()
            .any(|row| row.owner == grace_owner && row.expires == grace)
    {
        return Err(invalid("immediate re-pin lost original release grace"));
    }
    emit(&format!(
        "READY consumer re-pin {} {} {}; release grace retained without inode duplication",
        repinned.owner(),
        short_expiry,
        grace
    ))?;
    control("expiry")?;
    runtime
        .block_on(TokioClock.sleep(Duration::from_secs(short_expiry.saturating_sub(now()?) + 1)))?;
    let expired_bytes = fs::read(policy_path(inputs))?;
    if repinned.read_verified().is_ok()
        || runtime
            .block_on(owner.renew_consumer_lease(&repinned, short_expiry + 90))
            .is_ok()
        || fs::read(policy_path(inputs))? != expired_bytes
    {
        return Err(invalid(
            "expired lease read or renewal survived its original deadline",
        ));
    }
    let grace_duration = inputs.owner_config()?.policy.release_grace.as_secs();
    let final_deadline = grace.max(short_expiry + grace_duration);
    emit("EXPIRED actual consumer grant; renewal refused while durable grace remains")?;
    // The physical worker sweeps periodically. Do not issue a sweep or retry a
    // failed operation to manufacture the final durable-removal witness.
    runtime.block_on(TokioClock.sleep(Duration::from_secs(
        final_deadline.saturating_sub(now()?) + 3,
    )))?;
    let after = load(runtime, inputs)?;
    require_original(&baseline, &after)?;
    if after.pins.len() != baseline.pins.len()
        || after.leases.len() != baseline.leases.len()
        || after.reservations.len() != baseline.reservations.len()
        || published.handle().metadata()?.ino() != original_inode
        || repinned.read_verified().is_ok()
    {
        eprintln!("periodic consumer snapshot before failure: {after:?}");
        eprintln!("original producer snapshot: {baseline:?}");
        return Err(invalid(
            "periodic sweep failed original grace deadline or changed producer custody",
        ));
    }
    emit(
        "PASS native shared-directory sealed fallback, original grant, finite inventory, foreign-layout refusal, held-policy read and release revocation",
    )?;
    emit(
        "PASS actual consumer pin, held-policy read, cancelled renewal, foreign-owner refusal, release, re-pin and periodic expiry; original inode and producer records retained",
    )
}

fn foreign_control(
    lease: &NativeConsumerLease,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    confinement: Arc<quota_confinement::Installed>,
) -> io::Result<()> {
    // The supervisor provides a second independently provisioned domain. Its
    // genuine native preparation and Resume are required before misrouting.
    let foreign = Inputs {
        root: std::env::var("TERRANE_LEASE_FOREIGN_ROOT")
            .map_err(io::Error::other)?
            .into(),
        domain: "tenant:lease-foreign".into(),
        owner: "native-cache-lease-foreign".into(),
        project: std::env::var("TERRANE_LEASE_FOREIGN_PROJECT")
            .map_err(io::Error::other)?
            .parse()
            .map_err(io::Error::other)?,
        quota: inputs.quota.clone(),
        publisher: inputs.publisher.clone(),
        budget: inputs.budget,
        uuid: inputs.uuid,
    };
    let preparation = NativeCachePreparation::inspect(foreign.owner_config()?, confinement)?;
    let foreign_owner = NativeMetadataOwner::start(preparation)?;
    let completed = runtime.block_on(foreign_owner.recover())?;
    runtime
        .block_on(foreign_owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    let original = fs::read(policy_path(&foreign))?;
    if runtime
        .block_on(foreign_owner.renew_consumer_lease(lease, lease.expires_at()? + 1))
        .is_ok()
        || runtime
            .block_on(foreign_owner.release_consumer_lease(lease))
            .is_ok()
        || fs::read(policy_path(&foreign))? != original
    {
        return Err(invalid(
            "foreign actual physical owner mutated another consumer grant",
        ));
    }
    check_read(lease)
}

fn check_delta(
    baseline: &CacheState,
    actual: &CacheState,
    lease: &NativeConsumerLease,
    inputs: &Inputs,
    expires: u64,
    count: usize,
) -> io::Result<()> {
    require_original(baseline, actual)?;
    let token = lease
        .owner()
        .strip_prefix("consumer:")
        .ok_or_else(|| invalid("invalid consumer owner"))?;
    if actual.pins.len() != baseline.pins.len() + count
        || actual.leases.len() != baseline.leases.len() + count
        || actual.reservations.len() != baseline.reservations.len() + count
        || !actual.pins.iter().any(|row| {
            row.owner == lease.owner()
                && row.hash == hex(lease.identity().digest())
                && row.expires == expires
        })
        || !actual
            .leases
            .iter()
            .any(|row| row.owner == lease.owner() && row.expires == expires)
        || !actual
            .reservations
            .iter()
            .any(|row| row.id == token && row.owner == inputs.owner && row.bytes == HOLD)
    {
        return Err(invalid(
            "consumer acknowledgment lacks exact durable pin, lease and hold",
        ));
    }
    Ok(())
}

fn require_original(before: &CacheState, after: &CacheState) -> io::Result<()> {
    for row in &before.pins {
        if !after.pins.iter().any(|actual| {
            actual.owner == row.owner && actual.hash == row.hash && actual.expires == row.expires
        }) {
            return Err(invalid("consumer operation changed original pin"));
        }
    }
    for row in &before.leases {
        if !after
            .leases
            .iter()
            .any(|actual| actual.owner == row.owner && actual.expires == row.expires)
        {
            return Err(invalid("consumer operation changed original lease"));
        }
    }
    for row in &before.reservations {
        if !after.reservations.iter().any(|actual| {
            actual.id == row.id && actual.owner == row.owner && actual.bytes == row.bytes
        }) {
            return Err(invalid("consumer operation changed original hold"));
        }
    }
    if before.residences.len() != after.residences.len()
        || before
            .residences
            .iter()
            .zip(&after.residences)
            .any(|(a, b)| {
                a.chunk != b.chunk
                    || a.object != b.object
                    || a.offset != b.offset
                    || a.length != b.length
            })
    {
        return Err(invalid("consumer operation changed original residence"));
    }
    Ok(())
}

fn load(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<CacheState> {
    runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("consumer snapshot absent"))
}

fn policy_path(inputs: &Inputs) -> std::path::PathBuf {
    inputs.root.join("state/cache/records.toml")
}

fn check_read(lease: &NativeConsumerLease) -> io::Result<()> {
    if lease.read_verified()? != PLAINTEXT {
        return Err(invalid("consumer read differs from verified source"));
    }
    Ok(())
}

fn now() -> io::Result<u64> {
    TokioClock
        .now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(io::Error::other)
}

fn emit(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != expected {
        return Err(invalid("unexpected consumer fixture control"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
