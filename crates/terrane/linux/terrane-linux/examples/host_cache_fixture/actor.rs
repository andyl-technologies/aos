//! Executes actual empty recovery and conservative controls under native custody.

use super::config::{EPOCH, HARD_LIMIT, HOLD, Inputs, STATE};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    future::Future,
    io::{self, BufRead, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    sync::Arc,
    task::{Context, Poll, Waker},
};
use terrane_linux::{
    host_cache::{NativeCachePreparation, NativeMetadataOwner},
    host_quota::{HostQuotaClient, NativeProject},
    quota_confinement,
};
use terrane_sdk::{host::cache::CacheState, store::TokioLocalFs};

/// Runs one actual isolated component witness.
///
/// # Errors
/// Refuses unsupported kernel facts, configuration, custody or failed assertions.
pub(super) fn run(mode: &str) -> io::Result<()> {
    if !matches!(
        mode,
        "prepare"
            | "consumer-leases"
            | "empty"
            | "refuse"
            | "late-refuse"
            | "cancel"
            | "edquot"
            | "hold"
            | "start-refuse"
            | "admit-chunk"
            | "admit-metadata"
            | "admit-cancel"
            | "cache-admission-handoff"
            | "dictionary-custody"
            | "recover-manifest"
            | "recover-index-recovery"
            | "refuse-index-disabled"
            | "refuse-index-bound"
            | "refuse-index-mismatch"
            | "refuse-pending-inline"
            | "recover-pending-inline"
            | "refuse-pending-chunk"
            | "recover-pending-chunk"
            | "refuse-manifest"
            | "refuse-unsealed-manifest"
            | "refuse-unsealed-writable-manifest"
            | "refuse-truncated-manifest"
            | "recover-writable-manifest"
            | "recover-mixed-manifest"
            | "refuse-mixed-manifest"
            | "publish-inline"
            | "publish-inline-cancel"
            | "publish-inline-transfer"
            | "publish-inline-transfer-cancel"
            | "publish-inline-transfer-conflict"
            | "retain-running"
            | "retain-running-cancel"
            | "publish-manifest"
            | "publish-manifest-cancel"
            | "publish-manifest-bad-whole"
            | "publish-manifest-dictionary"
            | "publish-manifest-reuse"
            | "publish-manifest-reuse-bad-whole"
            | "source-cleanup"
            | "source-cleanup-early"
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
        "refuse-pending-inline"
        | "recover-pending-inline"
        | "refuse-pending-chunk"
        | "recover-pending-chunk" => {
            super::recovery::pending::run(mode, &owner, &runtime, &inputs)?;
        }
        "dictionary-custody" => {
            super::dictionary_custody::run(&owner, &runtime, &inputs, original)?;
        }
        "cache-admission-handoff" => {
            super::admission_cache::run(&owner, &runtime, &inputs, original)?;
        }
        "source-cleanup" | "source-cleanup-early" => {
            super::source_cleanup::run(
                mode,
                &owner,
                &runtime,
                &inputs,
                Arc::clone(&confinement),
                original,
            )?;
        }
        "consumer-leases" => {
            super::consumer::run(
                &owner,
                &runtime,
                &inputs,
                Arc::clone(&confinement),
                original,
            )?;
        }
        "publish-manifest"
        | "publish-manifest-cancel"
        | "publish-manifest-bad-whole"
        | "publish-manifest-dictionary"
        | "publish-manifest-reuse"
        | "publish-manifest-reuse-bad-whole" => {
            super::manifest_publication::run(mode, &owner, &runtime, &inputs, original)?;
        }
        "retain-running" | "retain-running-cancel" => {
            super::running_retention::run(mode, &owner, &runtime, &inputs, original)?;
        }
        "publish-inline"
        | "publish-inline-cancel"
        | "publish-inline-transfer"
        | "publish-inline-transfer-cancel"
        | "publish-inline-transfer-conflict" => {
            super::publication::run(mode, &owner, &runtime, &inputs, original)?;
        }
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
        "admit-chunk" | "admit-metadata" | "admit-cancel" => {
            super::admission::run(mode, &owner, &runtime, &inputs, original)?;
        }
        "recover-manifest"
        | "recover-index-recovery"
        | "refuse-index-disabled"
        | "refuse-index-bound"
        | "refuse-index-mismatch"
        | "refuse-manifest"
        | "refuse-unsealed-manifest"
        | "refuse-unsealed-writable-manifest"
        | "refuse-truncated-manifest"
        | "recover-writable-manifest"
        | "recover-mixed-manifest"
        | "refuse-mixed-manifest" => {
            super::recovery::run(mode, &owner, &runtime, &inputs, original)?;
        }
        "late-refuse" => late_refuse(&owner, &runtime, &inputs, original)?,
        "cancel" => cancel(&owner, &runtime, &inputs)?,
        "empty" | "edquot" => {
            let prior = runtime
                .block_on(CacheState::load(
                    &TokioLocalFs,
                    &inputs.root.join("state/cache"),
                    STATE,
                ))
                .map_err(io::Error::other)?
                .unwrap_or_default();
            let future = prior.reservations.iter().try_fold(HOLD, |sum, hold| {
                sum.checked_add(hold.bytes)
                    .ok_or_else(|| io::Error::other("fixture retained holds overflow"))
            })?;
            let completed = runtime.block_on(owner.recover())?;
            completed.check_current()?;
            if completed.synchronized_retained_inode_bytes() == 0
                || completed.synchronized_retained_inodes() < 8
                || completed.future_hold_bytes() != future
                || completed.charged_reserved_bytes() > HARD_LIMIT
            {
                return Err(io::Error::other("invalid actual empty recovery accounting"));
            }
            verify_holds(&runtime, &inputs, &prior)?;
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

// This fixture retains and compares the actual unknown inode; it does not turn
// an inventory candidate or durable reservation into native readiness evidence.
struct UnknownCandidate {
    file: File,
    metadata: Metadata,
    project: NativeProject,
    bytes: Vec<u8>,
}

impl UnknownCandidate {
    fn capture(inputs: &Inputs) -> io::Result<Self> {
        let retained = Self::open_name(inputs)?;
        let metadata = retained.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 840
            || metadata.gid() != 845
            || metadata.mode() & 0o7777 != 0o660
            || metadata.nlink() != 1
            || metadata.len() > 4096
        {
            return Err(io::Error::other("unexpected unknown fixture inode custody"));
        }
        // Classify with O_PATH before any readable open: no device is opened
        // and no FIFO can block. Procfs names only our live retained inode.
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOATIME)
            .open(format!("/proc/self/fd/{}", retained.as_raw_fd()))?;
        let opened = file.metadata()?;
        if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
            return Err(io::Error::other("unknown fixture readable inode changed"));
        }
        let project = NativeProject::inspect(&file)?;
        if project.project_id != inputs.project {
            return Err(io::Error::other("unknown fixture project differs"));
        }
        let mut bytes = Vec::new();
        (&mut file).take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 || bytes.len() as u64 != metadata.len() {
            return Err(io::Error::other(
                "unknown fixture bytes exceeded capture bound",
            ));
        }
        let named = Self::open_name(inputs)?.metadata()?;
        if named.dev() != metadata.dev() || named.ino() != metadata.ino() {
            return Err(io::Error::other(
                "unknown fixture pathname changed during capture",
            ));
        }
        Ok(Self {
            file,
            metadata,
            project,
            bytes,
        })
    }

    fn open_name(inputs: &Inputs) -> io::Result<File> {
        Ok(File::from(rustix::fs::openat2(
            rustix::fs::CWD,
            inputs.root.join("chunks/unrecognized-name"),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS,
        )?))
    }

    fn check_unchanged(&self, inputs: &Inputs) -> io::Result<()> {
        let current = Self::capture(inputs)?;
        // Access time is not a content-mutation signal. The fixture reads with
        // O_NOATIME, but an independent inventory read may legitimately touch it.
        for actual in [self.file.metadata()?, current.metadata] {
            let expected = &self.metadata;
            if actual.dev() != expected.dev()
                || actual.ino() != expected.ino()
                || actual.uid() != expected.uid()
                || actual.gid() != expected.gid()
                || actual.mode() != expected.mode()
                || actual.len() != expected.len()
                || actual.blocks() != expected.blocks()
                || actual.nlink() != expected.nlink()
                || actual.mtime() != expected.mtime()
                || actual.mtime_nsec() != expected.mtime_nsec()
                || actual.ctime() != expected.ctime()
                || actual.ctime_nsec() != expected.ctime_nsec()
            {
                return Err(io::Error::other(
                    "late refusal changed unknown inode metadata",
                ));
            }
        }
        if current.bytes != self.bytes
            || current.project != self.project
            || NativeProject::inspect(&self.file)? != self.project
        {
            return Err(io::Error::other(
                "late refusal changed unknown bytes or project",
            ));
        }
        Ok(())
    }
}

fn late_refuse(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    original: Option<Vec<u8>>,
) -> io::Result<()> {
    if inputs.domain != "tenant:unknown" || original.is_some() || snapshot(inputs)?.is_some() {
        return Err(io::Error::other(
            "late refusal requires the fresh unknown-only fixture",
        ));
    }
    let unknown = UnknownCandidate::capture(inputs)?;
    let error = runtime
        .block_on(owner.recover())
        .err()
        .ok_or_else(|| io::Error::other("unknown candidate unexpectedly completed recovery"))?;
    if error.kind() != io::ErrorKind::WouldBlock {
        return Err(io::Error::other(format!(
            "unexpected late recovery refusal: {error}"
        )));
    }
    verify_holds(runtime, inputs, &CacheState::default())?;
    let funded = snapshot(inputs)?
        .ok_or_else(|| io::Error::other("late refusal lost its durable funded snapshot"))?;
    unknown.check_unchanged(inputs)?;

    let error = runtime
        .block_on(owner.recover())
        .err()
        .ok_or_else(|| io::Error::other("faulted owner unexpectedly completed recovery"))?;
    if error.kind() != io::ErrorKind::WouldBlock
        || error.to_string() != "failed physical work requires native reconciliation"
    {
        return Err(io::Error::other(format!(
            "late refusal did not retain faulted custody: {error}"
        )));
    }
    verify_holds(runtime, inputs, &CacheState::default())?;
    if snapshot(inputs)?.as_ref() != Some(&funded) {
        return Err(io::Error::other(
            "faulted owner changed its durable funded snapshot",
        ));
    }
    unknown.check_unchanged(inputs)?;
    emit(
        "PASS actual late refusal retained funded hold, faulted custody and unchanged unknown inode; no Resume",
    )
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

fn verify_holds(
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
    prior: &CacheState,
) -> io::Result<()> {
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
        || state.reservations.len() != prior.reservations.len() + 1
        || state.reservations.iter().any(|hold| {
            hold.owner != inputs.owner
                || hold.bytes != HOLD
                || hold.id.len() != 32
                || !hold
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || !hold.id.bytes().any(|byte| byte != b'0')
        })
        || prior.reservations.iter().any(|old| {
            state
                .reservations
                .iter()
                .filter(|hold| {
                    hold.id == old.id && hold.owner == old.owner && hold.bytes == old.bytes
                })
                .count()
                != 1
        })
    {
        return Err(io::Error::other("actual durable bootstrap hold differs"));
    }
    Ok(())
}

fn cancel(
    owner: &NativeMetadataOwner,
    runtime: &tokio::runtime::Runtime,
    inputs: &Inputs,
) -> io::Result<()> {
    emit("READY actual preparation and owner; wait for stopped-helper control")?;
    require_control("enqueue")?;
    let mut request = Box::pin(owner.recover());
    let mut context = Context::from_waker(Waker::noop());
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
    // This exact refusal proves that the abandoned first command completed;
    // a faulted first command produces the distinct failed-work refusal. A
    // completed physical owner never restarts recovery or adds another hold.
    if error.kind() != io::ErrorKind::WouldBlock
        || error.to_string() != "native recovery already completed for this physical owner"
    {
        return Err(io::Error::other(format!(
            "cancel barrier did not reach cold-policy refusal: {error}"
        )));
    }
    verify_holds(runtime, inputs, &CacheState::default())?;
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
