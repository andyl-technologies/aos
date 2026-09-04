//! Retained direct-child ownership for planner cleanup and unwinding.
//!
//! Each supervisor starts one cleanup worker before launching any process. The
//! worker retains failed cleanup beyond the caller's finite wait; another
//! evaluation cannot overlap an unreaped child.

use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::sync::{Condvar, Mutex};

use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};

use super::*;

const CLEANUP_WAIT: Duration = Duration::from_secs(1);
const CLEANUP_RETRY: Duration = Duration::from_millis(10);

#[derive(Default)]
struct State {
    child: Option<Child>,
    requested: bool,
    closed: bool,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

pub(super) struct ProcessOwner {
    shared: Arc<Shared>,
}

impl ProcessOwner {
    pub(super) fn new() -> Result<Self, CanonicalPlannerProcessError> {
        let shared = Arc::new(Shared::default());
        let worker = Arc::clone(&shared);
        thread::Builder::new()
            .name(String::from("crucible-planner-reaper"))
            .spawn(move || reap_loop(worker))
            .map_err(|source| process_io("spawn-canonical-planner-reaper", source))?;
        Ok(Self { shared })
    }

    pub(super) fn run<T>(
        &self,
        command: &mut Command,
        operation: impl FnOnce(&mut Child) -> Result<T, CanonicalPlannerProcessError>,
    ) -> Result<T, CanonicalPlannerProcessError> {
        // Declared before the lock guard so unwinding releases the mutex
        // before requesting cleanup of any child installed by this call.
        let cleanup = RequestCleanup(&self.shared);
        let mut state = self.shared.state.lock().map_err(|_| {
            CanonicalPlannerProcessError::InvalidConfiguration(
                "canonical planner owner is poisoned",
            )
        })?;
        if state.child.is_some() || state.closed {
            return Err(CanonicalPlannerProcessError::CleanupPending);
        }
        // The configured executable is the trusted built-in worker. Its group
        // contains inherited pipes on subprocess failure; it is not a sandbox
        // for a program deliberately escaping that process group.
        state.child = Some(
            command
                .process_group(0)
                .spawn()
                .map_err(|source| process_io("spawn-canonical-planner", source))?,
        );
        let result = match state.child.as_mut() {
            Some(child) => operation(child),
            None => Err(CanonicalPlannerProcessError::InvalidConfiguration(
                "planner child ownership was lost",
            )),
        };
        drop(state);
        drop(cleanup);
        // A cleanup failure takes precedence over both a proposal and an
        // execution error. The worker still owns and retries the exact child.
        self.finish()?;
        result
    }

    fn finish(&self) -> Result<(), CanonicalPlannerProcessError> {
        let state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (state, _) = self
            .shared
            .changed
            .wait_timeout_while(state, CLEANUP_WAIT, |state| state.child.is_some())
            .unwrap_or_else(|error| error.into_inner());
        if state.child.is_some() {
            Err(CanonicalPlannerProcessError::CleanupPending)
        } else {
            Ok(())
        }
    }
}

struct RequestCleanup<'a>(&'a Shared);

impl Drop for RequestCleanup<'_> {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.requested = true;
        self.0.changed.notify_all();
    }
}

impl Drop for ProcessOwner {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        state.requested = true;
        self.shared.changed.notify_all();
    }
}

fn reap_loop(shared: Arc<Shared>) {
    let mut state = shared
        .state
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    loop {
        if !state.requested && !state.closed {
            state = shared
                .changed
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
            continue;
        }
        let completed = match state.child.as_mut() {
            None => true,
            Some(child) => reap_once(child),
        };
        if completed {
            state.child = None;
            state.requested = false;
            shared.changed.notify_all();
            if state.closed {
                return;
            }
        } else {
            let (next, _) = shared
                .changed
                .wait_timeout(state, CLEANUP_RETRY)
                .unwrap_or_else(|error| error.into_inner());
            state = next;
        }
    }
}

fn reap_once(child: &mut Child) -> bool {
    let Some(pid) = Pid::from_raw(child.id() as i32) else {
        return false;
    };
    // The exchange observes with WNOWAIT. Keep the leader waitable until after
    // signaling so a recycled PID cannot identify an unrelated process group.
    match kill_process_group(pid, Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => {}
        Err(_) => return false,
    }
    matches!(child.try_wait(), Ok(Some(_)))
}

pub(super) fn observe_exit(child: &Child) -> io::Result<Option<ExitStatus>> {
    let pid = Pid::from_raw(child.id() as i32)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let status = waitid(
        WaitId::Pid(pid),
        WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
    )?;
    match status {
        None => Ok(None),
        Some(status) => {
            let raw = if let Some(code) = status.exit_status() {
                code << 8
            } else if let Some(signal) = status.terminating_signal() {
                signal | if status.dumped() { 0x80 } else { 0 }
            } else {
                return Err(io::ErrorKind::InvalidData.into());
            };
            Ok(Some(ExitStatus::from_raw(raw)))
        }
    }
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- fixtures inject and localize owner failures.
#[allow(clippy::expect_used)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;
    use crate::planner_process::pipes::tests::child_command;

    #[test]
    fn unwinding_transfers_the_child_to_cleanup_before_owner_drop() {
        let owner = ProcessOwner::new().expect("owner");
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _result: Result<(), CanonicalPlannerProcessError> = owner
                .run(&mut child_command("blocked"), |_child| {
                    panic!("injected exchange panic")
                });
        }));
        assert!(panic.is_err());
        owner
            .finish()
            .expect("unwinding signaled cleanup without waiting for owner drop");
        let state = owner
            .shared
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert!(state.child.is_none());
    }

    #[test]
    fn pending_cleanup_retains_the_child_and_rejects_an_overlapping_launch() {
        let owner = ProcessOwner::new().expect("owner");
        let child = child_command("blocked")
            .process_group(0)
            .spawn()
            .expect("child");
        owner.shared.state.lock().expect("state").child = Some(child);
        // Deliberately hold the cleanup request to model an unfinished reap.
        assert!(matches!(
            owner.finish(),
            Err(CanonicalPlannerProcessError::CleanupPending)
        ));
        let result: Result<(), CanonicalPlannerProcessError> =
            owner.run(&mut Command::new("/must-not-be-launched"), |_| Ok(()));
        assert!(matches!(
            result,
            Err(CanonicalPlannerProcessError::CleanupPending)
        ));
        owner.finish().expect("exact child remains recoverable");
    }
}
