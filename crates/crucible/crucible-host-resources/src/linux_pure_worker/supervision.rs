//! Exact-child supervision, sticky cancellation and disk-output retirement.
//!
//! The prestarted supervisor retains the same State through every partial
//! failure. It publishes completion only after wait, empty cgroup and cleanup.

use super::*;

pub(super) fn launch_loop(shared: Arc<Shared>) {
    let command = {
        let mut state = lock(&shared);
        loop {
            if state.cancelled || state.launch_closed {
                state.launch_closed = true;
                return;
            }
            if let Some(command) = state.command.take() {
                state.launch_in_flight = true;
                break command;
            }
            state = shared
                .changed
                .wait(state)
                .unwrap_or_else(|p| p.into_inner());
        }
    };
    let mut command = command;
    // Recheck immediately before standard-library spawn. The installed
    // supervisor contract also excludes disposition writers and other reapers
    // throughout this operation; a snapshot cannot enforce that global rule.
    if check_wait_policy().is_err() {
        let mut state = lock(&shared);
        state.fail(LinuxPureWorkerFailure::Setup);
        state.launch_in_flight = false;
        state.launch_closed = true;
        shared.changed.notify_all();
        return;
    }
    let spawned = command.spawn();
    let mut state = lock(&shared);
    // No fallible observation/allocation between successful spawn and adoption.
    match spawned {
        Ok(child) => {
            state.child_id = Some(child.id());
            state.child = Some(child);
        }
        Err(_) => state.fail(LinuxPureWorkerFailure::Setup),
    }
    state.launch_in_flight = false;
    state.launch_closed = true;
    shared.changed.notify_all();
}

pub(super) fn collect<R: Read>(
    pipe: &mut Option<R>,
    output: &mut Vec<u8>,
    maximum: usize,
) -> Result<(), LinuxPureWorkerFailure> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0_u8; 8192];
    match reader.read(&mut buffer) {
        Ok(0) => {
            *pipe = None;
            Ok(())
        }
        Ok(count) => {
            if output.len().checked_add(count).is_none_or(|v| v > maximum) {
                return Err(LinuxPureWorkerFailure::StdoutLimit);
            }
            output
                .try_reserve_exact(count)
                .map_err(|_| LinuxPureWorkerFailure::OutputAllocation)?;
            output.extend_from_slice(&buffer[..count]);
            Ok(())
        }
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            Ok(())
        }
        Err(_) => Err(LinuxPureWorkerFailure::OutputIo),
    }
}

fn load_output(
    mut file: Option<File>,
    output: &mut Vec<u8>,
    maximum: usize,
) -> Result<(), LinuxPureWorkerFailure> {
    if let Some(file) = file.as_mut() {
        file.seek(SeekFrom::Start(0))
            .map_err(|_| LinuxPureWorkerFailure::OutputIo)?;
    }
    while file.is_some() {
        collect(&mut file, output, maximum)?;
    }
    Ok(())
}

pub(super) fn supervise(shared: Arc<Shared>) {
    loop {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| step(&shared)));
        match result {
            Ok(true) => return,
            Ok(false) => thread::sleep(Duration::from_millis(10)),
            Err(_) => loop {
                thread::park();
            }, // exact Shared/Child/limits remain owned
        }
    }
}

fn step(shared: &Shared) -> bool {
    let mut state = lock(shared);
    let mut expired = [0_u8; 8];
    match state.timer.read(&mut expired) {
        Ok(8) => state.fail(LinuxPureWorkerFailure::Timeout),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Ok(0) => (),
        _ => state.fail(LinuxPureWorkerFailure::Setup),
    }
    if !state.started && !state.cancelled {
        return false;
    }
    if state.cancelled {
        if let Some(group) = state.group.as_ref() {
            let _ = group.kill();
        }
        if let Some(child) = state.child.as_mut() {
            let _ = child.kill();
        }
        state.command = None;
        shared.changed.notify_all();
    }
    let out_size = state.out.as_ref().map(File::metadata).transpose();
    let err_size = state.err.as_ref().map(File::metadata).transpose();
    for (result, maximum, failure) in [
        (
            out_size,
            state.limits.stdout_bytes,
            LinuxPureWorkerFailure::StdoutLimit,
        ),
        (
            err_size,
            state.limits.stderr_bytes,
            LinuxPureWorkerFailure::StderrLimit,
        ),
    ] {
        match result {
            Ok(Some(metadata)) if metadata.len() > maximum as u64 => {
                state.fail(failure);
                break;
            }
            Err(_) => {
                state.fail(LinuxPureWorkerFailure::OutputIo);
                break;
            }
            _ => (),
        }
    }
    if let Some(child) = state.child.as_mut() {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    state.fail(LinuxPureWorkerFailure::ChildExit);
                }
                state.status = Some(status);
                state.child = None;
            }
            Ok(None) => (),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => (),
            Err(_) => {
                state.fail(LinuxPureWorkerFailure::Wait);
                return false;
            }
        }
    }
    if state.launch_in_flight || !state.launch_closed || state.child.is_some() {
        return false;
    }
    if let Some(group) = state.group.as_mut() {
        let delta = match group.oom_kill_delta() {
            Ok(delta) => delta,
            Err(_) => return false,
        };
        if group.remove_if_empty().is_err() {
            return false;
        }
        state.memory_oom_kills = delta;
    }
    state.group = None;
    state.input = None;
    if !state.outputs_collected {
        let State {
            out,
            err,
            stdout,
            stderr,
            limits,
            ..
        } = &mut *state;
        let out_result = load_output(out.take(), stdout, limits.stdout_bytes);
        let err_result = load_output(err.take(), stderr, limits.stderr_bytes).map_err(|error| {
            if error == LinuxPureWorkerFailure::StdoutLimit {
                LinuxPureWorkerFailure::StderrLimit
            } else {
                error
            }
        });
        if let Err(error) = out_result {
            state.fail(error);
        }
        if let Err(error) = err_result {
            state.fail(error);
        }
        state.outputs_collected = true;
    }
    if let Some(workspace) = state.workspace.as_mut()
        && workspace.release().is_err()
    {
        return false;
    }
    state.workspace = None;
    // Publish slot reuse once, before exposing completion. An old supervisor
    // must never clear the busy flag of a subsequently reserved occurrence.
    shared.busy.store(false, Ordering::Release);
    state.released = true;
    true
}
