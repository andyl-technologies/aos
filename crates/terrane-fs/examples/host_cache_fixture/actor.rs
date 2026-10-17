//! Executes actual empty recovery and conservative controls under native custody.

use super::config::{EPOCH, HARD_LIMIT, HOLD, Inputs, STATE};
use std::{
    fs::{self, OpenOptions},
    future::Future,
    io::{self, BufRead, Write},
    os::unix::fs::OpenOptionsExt,
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};
use terrane::{host::cache::CacheState, store::TokioLocalFs};
use terrane_fs::{
    host_cache::{NativeCachePreparation, NativeMetadataOwner},
    host_quota::{HostQuotaClient, NativeProject},
    quota_confinement,
};

/// Runs one actual isolated component witness.
///
/// # Errors
/// Refuses unsupported kernel facts, configuration, custody or failed assertions.
pub(super) fn run(mode: &str) -> io::Result<()> {
    if !matches!(
        mode,
        "prepare" | "empty" | "refuse" | "cancel" | "edquot" | "hold" | "start-refuse"
    ) {
        return Err(io::Error::other("unknown component selector"));
    }
    require_empty_capabilities()?;
    let confinement = Arc::new(quota_confinement::install()?);
    let inputs = Inputs::load()?;
    let preparation = NativeCachePreparation::inspect(inputs.owner_config()?, confinement.clone())?;
    confinement.check_current()?;
    if mode == "prepare" {
        emit("PASS actual native preparation; no recovery or Resume")?;
        return Ok(());
    }
    let original = snapshot(&inputs)?;
    let started = NativeMetadataOwner::start(preparation);
    if mode == "start-refuse" {
        let error = started
            .err()
            .ok_or_else(|| io::Error::other("exclusive owner unexpectedly duplicated"))?;
        if error.kind() != io::ErrorKind::WouldBlock || snapshot(&inputs)? != original {
            return Err(io::Error::other(
                "exclusive owner refusal changed state or error kind",
            ));
        }
        emit("PASS actual second state owner refused without mutation")?;
        return require_empty_capabilities();
    }
    let owner = started?;
    if mode == "hold" {
        emit("READY actual exclusive state owner retained")?;
        require_control("release")?;
        emit("PASS actual exclusive state owner released")?;
        return require_empty_capabilities();
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match mode {
        "refuse" => {
            let error = runtime
                .block_on(owner.recover())
                .err()
                .ok_or_else(|| io::Error::other("unresolved candidate unexpectedly recovered"))?;
            if error.kind() != io::ErrorKind::WouldBlock {
                return Err(io::Error::other(format!(
                    "unexpected recovery refusal: {error}"
                )));
            }
            let current = snapshot(&inputs)?;
            if current != original {
                return Err(io::Error::other("refused cold candidate snapshot changed"));
            }
            emit("PASS unresolved actual candidate refused without clearing state")?;
        }
        "cancel" => cancel(&owner, &runtime, &inputs)?,
        "empty" | "edquot" => {
            let completed = runtime.block_on(owner.recover())?;
            completed.check_current()?;
            if completed.synchronized_retained_inode_bytes() == 0
                || completed.synchronized_retained_inodes() < 8
                || completed.future_hold_bytes() != HOLD
                || completed.charged_reserved_bytes() > HARD_LIMIT
            {
                return Err(io::Error::other("invalid actual empty recovery accounting"));
            }
            verify_hold(&runtime, &inputs)?;
            emit(&format!(
                "PASS actual empty recovery retained_inode_bytes={} retained_inodes={} charged_reserved_bytes={} future_hold_bytes={}",
                completed.synchronized_retained_inode_bytes(),
                completed.synchronized_retained_inodes(),
                completed.charged_reserved_bytes(),
                completed.future_hold_bytes()
            ))?;
            if mode == "edquot" {
                edquot(&inputs)?;
                if completed.check_current().is_ok() {
                    return Err(io::Error::other(
                        "namespace mutation left old receipt current",
                    ));
                }
            }
        }
        _ => return Err(io::Error::other("unreachable selector")),
    }
    confinement.check_current()?;
    require_empty_capabilities()
}

fn snapshot(inputs: &Inputs) -> io::Result<Option<Vec<u8>>> {
    match fs::read(inputs.root.join("state/cache/records.toml")) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn require_empty_capabilities() -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 840 {
        return Err(io::Error::other("cache actor UID must be 840"));
    }
    let status = fs::read_to_string("/proc/self/status")?;
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let expected = format!("{field}:\t0000000000000000");
        if !status.lines().any(|line| line == expected) {
            return Err(io::Error::other(format!(
                "actual actor {field} is not empty"
            )));
        }
    }
    Ok(())
}

fn verify_hold(runtime: &tokio::runtime::Runtime, inputs: &Inputs) -> io::Result<()> {
    let state = runtime
        .block_on(CacheState::load(
            &TokioLocalFs,
            &inputs.root.join("state/cache"),
            STATE,
        ))
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("durable snapshot missing"))?;
    if !state.pins.is_empty()
        || !state.leases.is_empty()
        || !state.residences.is_empty()
        || state.reservations.len() != 1
        || state.reservations[0].owner != inputs.owner
        || state.reservations[0].bytes != HOLD
    {
        return Err(io::Error::other("actual durable bootstrap hold differs"));
    }
    Ok(())
}

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn cancel(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    emit("READY actual preparation and owner; wait for stopped-helper control")?;
    require_control("enqueue")?;
    let mut request = Box::pin(owner.recover());
    let waker = Waker::from(Arc::new(NoopWake));
    let mut context = Context::from_waker(&waker);
    if !matches!(request.as_mut().poll(&mut context), Poll::Pending) {
        return Err(io::Error::other(
            "cancellation did not observe accepted pending command",
        ));
    }
    drop(request);
    emit("CANCELLED accepted pending waiter; physical owner retained")?;
    require_control("resumed")?;
    let error = runtime
        .block_on(owner.recover())
        .err()
        .ok_or_else(|| io::Error::other("serialized barrier unexpectedly cleared prior hold"))?;
    // This fixture-only diagnostic distinguishes successful physical work
    // followed by refusal to erase its cold hold from the earlier faulted-owner
    // branch, which also returns WouldBlock after a late failed command.
    if error.kind() != io::ErrorKind::WouldBlock
        || error.to_string() != "cold policy records require actual native reconciliation"
    {
        return Err(io::Error::other(format!(
            "cancel barrier did not reach cold-policy refusal: {error}"
        )));
    }
    verify_hold(runtime, inputs)?;
    let mut client = HostQuotaClient::connect(&inputs.quota, 0, EPOCH)?;
    let observation = client.query(&inputs.owner, &inputs.domain)?;
    if observation.observation().hard_limit_bytes != HARD_LIMIT {
        return Err(io::Error::other(
            "cancel completion lacks actual quota custody",
        ));
    }
    emit("PASS cancelled waiter retained physical completion and durable hold")
}

fn require_control(expected: &str) -> io::Result<()> {
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    if line.trim_end() != expected {
        return Err(io::Error::other("unexpected bounded supervisor control"));
    }
    Ok(())
}

fn edquot(inputs: &Inputs) -> io::Result<()> {
    let path = inputs.root.join("chunks/quota-fill-component");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o660)
        .open(&path)?;
    if NativeProject::inspect(&file)?.project_id != inputs.project {
        return Err(io::Error::other("real filler escaped configured project"));
    }
    let bytes = [0x5a; 65536];
    let mut written = 0_u64;
    let error = loop {
        match file.write_all(&bytes) {
            Ok(()) => {
                written += bytes.len() as u64;
                if written > HARD_LIMIT + 1024 * 1024 {
                    return Err(io::Error::other(
                        "finite native quota failed to stop allocation",
                    ));
                }
            }
            Err(error) => break error,
        }
    };
    if written == 0 || error.raw_os_error() != Some(libc::EDQUOT) {
        return Err(io::Error::other(format!(
            "expected positive real EDQUOT, got {error}"
        )));
    }
    drop(file);
    let mut client = HostQuotaClient::connect(&inputs.quota, 0, EPOCH)?;
    let quota = client.query(&inputs.owner, &inputs.domain)?;
    if quota.observation().charged_reserved_bytes > HARD_LIMIT {
        return Err(io::Error::other(
            "kernel charged usage exceeded finite project limit",
        ));
    }
    emit(&format!(
        "PASS actual EDQUOT after at_least_bytes={written}; no admission or BKT15 claim"
    ))
}

fn emit(message: &str) -> io::Result<()> {
    let mut output = io::stdout().lock();
    writeln!(output, "{message}")?;
    output.flush()
}
