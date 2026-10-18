//! Exercises real Running inline publication and abandoned response waiters.
//!
//! Fixture bytes confer no authority. Every operation uses actual recovery,
//! acknowledged Resume, synchronized funding and the native publisher channel.
//! These component cases establish no consumer lease or bucket readiness.

#[path = "publication/transfer.rs"]
mod transfer;

use super::config::{HARD_LIMIT, HOLD, Inputs, STATE};
use std::{
    fs,
    future::Future,
    io::{self, BufRead, Write},
    os::unix::fs::{FileExt, MetadataExt},
    task::{Context, Poll, Waker},
};
use terrane::{host::cache::CacheState, store::TokioLocalFs};
use terrane_core::identity::{Descriptor, IdentityKind, TERRANE_V1};
use terrane_fs::{
    host_cache::{NativeInlinePublication, NativeMetadataOwner},
    host_quota::NativeProject,
};

const PLAINTEXT: &[u8] = b"actual owned inline publication bytes";

/// Executes actual publication or cancellation on a distinct finite native owner.
///
/// # Errors
/// Refuses a reused fixture, incorrect native bytes/funding, failed genuine
/// recovery/Resume, premature publication or lost physical completion.
pub(super) fn run(
    mode: &str,
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    let case = match mode {
        "publish-inline" => "tenant:publication-inline",
        "publish-inline-cancel" => "tenant:publication-cancel",
        "publish-inline-transfer" => "tenant:publication-transfer",
        "publish-inline-transfer-cancel" => "tenant:publication-transfer-cancel",
        "publish-inline-transfer-conflict" => "tenant:publication-transfer-conflict",
        _ => return Err(invalid("unknown inline publication selector")),
    };
    if inputs.domain != case || original.is_some() {
        return Err(invalid(
            "inline publication requires its fresh dedicated domain",
        ));
    }
    let completed = runtime.block_on(owner.recover())?;
    completed.check_current()?;
    let before = fs::read(inputs.root.join("state/cache/records.toml"))?;
    if runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .is_ok()
        || fs::read(inputs.root.join("state/cache/records.toml"))? != before
    {
        return Err(invalid("publication before Resume changed physical policy"));
    }
    runtime
        .block_on(owner.resume_recovered(completed))
        .map_err(io::Error::other)?;
    if mode.starts_with("publish-inline-transfer") {
        return transfer::run(mode, owner, runtime, inputs);
    }
    if mode == "publish-inline-cancel" {
        return cancelled(owner, runtime, inputs);
    }
    // More refusals than the finite registry's capacity must remain effect-free.
    for _ in 0..=STATE.records {
        let mut corrupt = encoded();
        corrupt[1] ^= 1;
        if runtime
            .block_on(owner.publish_inline(descriptor()?, corrupt))
            .is_ok()
            || fs::read(inputs.root.join("state/cache/records.toml"))? != before
        {
            return Err(invalid("invalid inline bytes changed durable funding"));
        }
    }
    let first = runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .map_err(io::Error::other)?;
    check_result(&first, inputs, 1, 0)?;
    check_policy(runtime, inputs, 1, 0)?;
    let inode = first.handle().metadata()?.ino();
    let second = runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .map_err(io::Error::other)?;
    check_result(&second, inputs, 2, 0)?;
    check_policy(runtime, inputs, 2, 0)?;
    if second.handle().metadata()?.ino() != inode {
        return Err(invalid(
            "no-replace publication replaced the original inode",
        ));
    }
    // A later legitimate state mutation must not invalidate immutable backing
    // reads or cause them to consult the original completed-recovery snapshot.
    read_plaintext(&first)?;
    emit(
        "PASS actual inline publication verified bytes, retained funding and no-replace inode; no Ready",
    )
}

fn cancelled(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    emit(
        "READY actual inline publication Resume acknowledged; wait for stopped-publisher control",
    )?;
    control("start")?;
    let mut pending = Box::pin(owner.publish_inline(descriptor()?, encoded()));
    let waker = Waker::noop();
    if !matches!(
        pending.as_mut().poll(&mut Context::from_waker(waker)),
        Poll::Pending
    ) {
        return Err(invalid(
            "stopped publisher did not retain a pending inline waiter",
        ));
    }
    emit("QUEUED actual inline publication; wait for durable funding control")?;
    control("cancel")?;
    drop(pending);
    emit("CANCELLED actual inline publication waiter; physical owner retained")?;
    control("finish")?;
    // This command is serialized behind the abandoned one. The supervisor first
    // observes its actual canonical inode and completed durable residence.
    let repeated = runtime
        .block_on(owner.publish_inline(descriptor()?, encoded()))
        .map_err(io::Error::other)?;
    check_result(&repeated, inputs, 2, 0)?;
    check_policy(runtime, inputs, 2, 0)?;
    emit(
        "PASS dropped inline waiter retained physical publication, canonical inode and durable holds; no Ready",
    )
}

fn check_result(
    result: &NativeInlinePublication,
    inputs: &Inputs,
    publications: u64,
    admissions: u64,
) -> io::Result<()> {
    let metadata = result.handle().metadata()?;
    if result.claim().descriptor() != &descriptor()?
        || result.claim().domain() != inputs.domain
        || metadata.uid() != 841
        || metadata.gid() != 841
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() != PLAINTEXT.len() as u64
        || NativeProject::inspect(result.handle())?.project_id != inputs.project
        || result.synchronized_sealed_inode_bytes() == 0
        || result.charged_reserved_bytes() > HARD_LIMIT
        || result.future_hold_bytes()
            != HOLD + publications * HOLD + admissions * (HOLD + encoded().len() as u64)
    {
        return Err(invalid(
            "inline result lacks actual native custody or accounting",
        ));
    }
    let flags = rustix::fs::fcntl_getfl(result.handle())?;
    if flags.intersects(
        rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::RDWR | rustix::fs::OFlags::PATH,
    ) {
        return Err(invalid("inline result descriptor is not read-only"));
    }
    terrane_fs::verity::measure(result.handle())?;
    read_plaintext(result)
}

fn read_plaintext(result: &NativeInlinePublication) -> io::Result<()> {
    let mut bytes = vec![0; PLAINTEXT.len()];
    result.handle().read_exact_at(&mut bytes, 0)?;
    if bytes != PLAINTEXT {
        return Err(invalid("actual sealed publication plaintext differs"));
    }
    Ok(())
}

fn check_policy(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    publications: usize,
    admissions: usize,
) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| invalid("inline publication snapshot absent"))?;
    let hash = hex(descriptor()?.digest());
    if state.reservations.len() != publications + admissions + 1
        || state.pins.len() != publications + admissions
        || state.leases.len() != publications + admissions
        || state.residences.len() != 1
    {
        return Err(invalid("inline publication policy closure differs"));
    }
    for row in &state.reservations {
        let expected = if state
            .leases
            .iter()
            .any(|lease| lease.owner == format!("publication:{}", row.id))
        {
            HOLD
        } else if state
            .leases
            .iter()
            .any(|lease| lease.owner == format!("admission:{}", row.id))
        {
            HOLD + encoded().len() as u64
        } else {
            HOLD
        };
        if row.owner != inputs.owner || row.bytes != expected {
            return Err(invalid("inline publication reservation differs"));
        }
    }
    if state
        .leases
        .iter()
        .filter(|lease| lease.owner.starts_with("admission:"))
        .count()
        != admissions
        || state
            .leases
            .iter()
            .filter(|lease| lease.owner.starts_with("publication:"))
            .count()
            != publications
    {
        return Err(invalid(
            "inline publication admission/publication pin classes differ",
        ));
    }
    for lease in &state.leases {
        if lease.expires != i64::MAX as u64
            || !(lease.owner.starts_with("publication:")
                || admissions > 0 && lease.owner.starts_with("admission:"))
            || state
                .pins
                .iter()
                .filter(|pin| {
                    pin.owner == lease.owner && pin.hash == hash && pin.expires == lease.expires
                })
                .count()
                != 1
        {
            return Err(invalid("inline publication lost its actual durable pin"));
        }
    }
    let row = &state.residences[0];
    if row.chunk != hash
        || row.object != hash
        || row.offset != 0
        || row.length != PLAINTEXT.len() as u64
    {
        return Err(invalid("inline publication residence differs"));
    }
    Ok(())
}

fn descriptor() -> io::Result<Descriptor> {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, PLAINTEXT)
        .map_err(io::Error::other)?;
    Descriptor::from_identity(&TERRANE_V1, &identity, PLAINTEXT).map_err(io::Error::other)
}

fn encoded() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(PLAINTEXT.len() + 1);
    bytes.push(0);
    bytes.extend_from_slice(PLAINTEXT);
    bytes
}

fn emit(message: &str) -> io::Result<()> {
    println!("{message}");
    io::stdout().flush()
}

fn control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim() != expected {
        return Err(invalid("unexpected inline publication control"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
