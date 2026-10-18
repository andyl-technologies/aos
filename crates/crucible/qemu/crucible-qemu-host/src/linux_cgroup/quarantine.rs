//! Nondroppable cleanup ownership for one failed QEMU process generation.
//!
//! This module composes the authorities that must survive a failed live
//! realization: every retained direct-child wait handle, the persistent cgroup
//! cancellation watcher when it has not already joined, and the pinned
//! configured cgroup. Cleanup runs on a dedicated detached worker. Dropping the
//! observation handle cannot stop that worker or release any authority.
//! Ordinary host errors retry at a fixed cadence; an invariant panic is caught
//! once and parks the worker forever with every remaining authority still
//! owned.

use std::collections::VecDeque;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread;

use thiserror::Error;

use super::{
    CGROUP_KILL_INTERVAL, LinuxQemuCgroup, LinuxQemuCgroupError, LinuxQemuCgroupWatcher,
    QemuNodeChild, WATCHER_TERMINAL,
};

const QUARANTINE_RUNNING: u8 = 0;
const QUARANTINE_RELEASED: u8 = 1;
const QUARANTINE_PARKED: u8 = 2;

/// Observable terminal state of one nondroppable process quarantine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxQemuAttemptProcessQuarantineStatus {
    /// The worker still owns and is cleaning at least one authority.
    Running,
    /// Direct-child reap, watcher completion, and cgroup removal all completed.
    ReapedAndReleased,
    /// An invariant panic parked the worker with all remaining authority.
    ParkedWithAuthority,
}

/// Observation handle for one detached, nondroppable QEMU process quarantine.
///
/// The handle owns no cleanup capability. Dropping it merely stops observation;
/// the detached worker continues until cleanup succeeds or it parks after an
/// invariant panic.
#[derive(Debug)]
#[must_use = "retain the handle to observe quarantine completion"]
pub(crate) struct LinuxQemuAttemptProcessQuarantine {
    status: Arc<AtomicU8>,
}

#[derive(Debug)]
struct LinuxQemuAttemptProcessQuarantineState {
    group: Option<LinuxQemuCgroup>,
    watcher: Option<LinuxQemuCgroupWatcher>,
    children: VecDeque<LinuxQemuQuarantineChild>,
}

#[derive(Debug)]
struct LinuxQemuQuarantineChild {
    child: QemuNodeChild,
    cgroup_path: PathBuf,
    attempt_lifecycle: Arc<AtomicU8>,
}

/// Failed process-quarantine startup with every untransferred authority retained.
#[derive(Debug, Error)]
#[error("failed to start QEMU process quarantine: {source}")]
#[must_use = "recover the authorities or leave this error to leak them fail-closed"]
pub(crate) struct LinuxQemuAttemptProcessQuarantineStartError {
    source: LinuxQemuCgroupError,
    authority: Option<Box<LinuxQemuAttemptProcessQuarantineState>>,
}

impl LinuxQemuAttemptProcessQuarantineStartError {
    pub(super) fn into_owner_parts(
        mut self,
    ) -> Option<(
        LinuxQemuCgroup,
        Option<LinuxQemuCgroupWatcher>,
        VecDeque<QemuNodeChild>,
    )> {
        let mut state = *self.authority.take()?;
        let group = state.group.take()?;
        let watcher = state.watcher.take();
        let children = state
            .children
            .drain(..)
            .map(LinuxQemuQuarantineChild::into_child)
            .collect();
        Some((group, watcher, children))
    }
}

impl Drop for LinuxQemuAttemptProcessQuarantineStartError {
    fn drop(&mut self) {
        if let Some(authority) = self.authority.take() {
            // An ignored startup error must not invoke the bounded child
            // destructor or release cgroup controls. This deliberate leak is
            // a fail-closed last resort when no worker accepted ownership.
            let _leaked = Box::leak(authority);
        }
    }
}

trait QuarantineWork: Send + 'static {
    type Error;

    fn reap_and_release(&mut self) -> Result<(), Self::Error>;
}

impl LinuxQemuAttemptProcessQuarantine {
    pub(super) fn start_retained(
        group: LinuxQemuCgroup,
        watcher: Option<LinuxQemuCgroupWatcher>,
        children: VecDeque<QemuNodeChild>,
    ) -> Result<Self, LinuxQemuAttemptProcessQuarantineStartError> {
        let path = group.path.clone();
        let attempt_lifecycle = Arc::clone(&group.control.watcher_state);
        let children = children
            .into_iter()
            .map(|child| LinuxQemuQuarantineChild {
                child,
                cgroup_path: path.clone(),
                attempt_lifecycle: Arc::clone(&attempt_lifecycle),
            })
            .collect();
        let state = LinuxQemuAttemptProcessQuarantineState {
            group: Some(group),
            watcher,
            children,
        };
        Self::start_state(path, state)
    }

    fn start_state(
        path: PathBuf,
        state: LinuxQemuAttemptProcessQuarantineState,
    ) -> Result<Self, LinuxQemuAttemptProcessQuarantineStartError> {
        if !state.authority_matches() {
            return Err(LinuxQemuAttemptProcessQuarantineStartError {
                source: LinuxQemuCgroupError::ProcessMembership { path },
                authority: Some(Box::new(state)),
            });
        }
        start_worker(state).map_err(
            |(source, state)| LinuxQemuAttemptProcessQuarantineStartError {
                source: LinuxQemuCgroupError::Io {
                    operation: "spawn QEMU process quarantine worker",
                    path: state
                        .as_ref()
                        .and_then(|state| state.group.as_ref())
                        .map_or_else(|| path.clone(), |group| group.path.clone()),
                    source,
                },
                authority: state.map(Box::new),
            },
        )
    }

    /// Returns the latest process-quarantine status.
    #[must_use]
    pub(crate) fn status(&self) -> LinuxQemuAttemptProcessQuarantineStatus {
        decode_status(self.status.load(Ordering::Acquire))
    }
}

impl LinuxQemuAttemptProcessQuarantineState {
    fn authority_matches(&self) -> bool {
        let Some(group) = &self.group else {
            return false;
        };
        let watcher_matches = self.watcher.as_ref().map_or_else(
            || group.control.watcher_state.load(Ordering::Acquire) == WATCHER_TERMINAL,
            |watcher| {
                group.path == watcher.path
                    && Arc::ptr_eq(&group.control.watcher_state, &watcher.watcher_state)
            },
        );
        watcher_matches
            && self
                .children
                .iter()
                .all(|child| child.authority_matches(group))
    }
}

impl LinuxQemuQuarantineChild {
    fn authority_matches(&self, group: &LinuxQemuCgroup) -> bool {
        group.path == self.cgroup_path
            && Arc::ptr_eq(&group.control.watcher_state, &self.attempt_lifecycle)
    }

    fn kill_and_reap_blocking(&mut self) -> Result<(), LinuxQemuCgroupError> {
        self.child
            .force_kill_and_reap_failed_realization()
            .map_err(|source| LinuxQemuCgroupError::Io {
                operation: "kill and reap retained unverified QEMU direct child",
                path: self.cgroup_path.clone(),
                source: io::Error::other(source),
            })
    }

    fn into_child(self) -> QemuNodeChild {
        self.child
    }
}

impl QuarantineWork for LinuxQemuAttemptProcessQuarantineState {
    type Error = LinuxQemuCgroupError;

    fn reap_and_release(&mut self) -> Result<(), Self::Error> {
        let group = self
            .group
            .as_mut()
            .ok_or_else(|| LinuxQemuCgroupError::Io {
                operation: "recover QEMU process quarantine cgroup",
                path: std::path::PathBuf::from("<released>"),
                source: io::Error::other("quarantine cgroup authority is absent"),
            })?;
        group.control.signal_cancellation()?;
        group.control.kill_members()?;

        while let Some(child) = self.children.front_mut() {
            child.kill_and_reap_blocking()?;
            self.children.pop_front();
        }

        if group.is_populated()? {
            return Err(LinuxQemuCgroupError::InvalidEvents {
                path: group.path.clone(),
                message: String::from(
                    "quarantined cgroup remained populated after direct-child reap",
                ),
            });
        }

        if let Some(watcher) = self.watcher.as_mut() {
            let joined = watcher.join_terminal_blocking();
            self.watcher = None;
            joined?;
        }

        group.remove_if_empty_in_place()?;
        self.group = None;
        Ok(())
    }
}

fn start_worker<W>(work: W) -> Result<LinuxQemuAttemptProcessQuarantine, (io::Error, Option<W>)>
where
    W: QuarantineWork,
{
    let authority = Arc::new(std::sync::Mutex::new(Some(work)));
    let worker_authority = Arc::clone(&authority);
    let status = Arc::new(AtomicU8::new(QUARANTINE_RUNNING));
    let worker_status = Arc::clone(&status);
    let spawn = thread::Builder::new()
        .name(String::from("crucible-qemu-quarantine"))
        .spawn(move || {
            let mut work = {
                let mut authority = match worker_authority.lock() {
                    Ok(authority) => authority,
                    Err(poisoned) => poisoned.into_inner(),
                };
                match authority.take() {
                    Some(work) => work,
                    None => return,
                }
            };
            loop {
                match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    work.reap_and_release()
                })) {
                    Ok(Ok(())) => {
                        worker_status.store(QUARANTINE_RELEASED, Ordering::Release);
                        return;
                    }
                    Ok(Err(_)) => thread::sleep(CGROUP_KILL_INTERVAL),
                    Err(_) => {
                        worker_status.store(QUARANTINE_PARKED, Ordering::Release);
                        // Re-entering code after an invariant panic would trust
                        // partially invalidated local invariants. Parking retains
                        // `work` and every authority it still owns.
                        loop {
                            thread::park();
                        }
                    }
                }
            }
        });
    if let Err(source) = spawn {
        let work = match Arc::try_unwrap(authority) {
            Ok(authority) => match authority.into_inner() {
                Ok(work) => work,
                Err(poisoned) => poisoned.into_inner(),
            },
            Err(authority) => {
                // The rejected closure should have dropped its only clone. If
                // it did not, retain the shared cell forever rather than risk
                // dropping opaque cleanup authority.
                let _leaked = Arc::into_raw(authority);
                None
            }
        };
        return Err((source, work));
    }
    drop(authority);
    Ok(LinuxQemuAttemptProcessQuarantine { status })
}

fn decode_status(status: u8) -> LinuxQemuAttemptProcessQuarantineStatus {
    match status {
        QUARANTINE_RELEASED => LinuxQemuAttemptProcessQuarantineStatus::ReapedAndReleased,
        QUARANTINE_PARKED => LinuxQemuAttemptProcessQuarantineStatus::ParkedWithAuthority,
        _ => LinuxQemuAttemptProcessQuarantineStatus::Running,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::time::Duration;

    use rustix::time::{ClockId, clock_gettime};

    use super::*;

    fn wait_for_status(
        quarantine: &LinuxQemuAttemptProcessQuarantine,
        timeout: Duration,
    ) -> LinuxQemuAttemptProcessQuarantineStatus {
        let Some(started) = Duration::try_from(clock_gettime(ClockId::Monotonic)).ok() else {
            return quarantine.status();
        };
        let Some(deadline) = started.checked_add(timeout) else {
            return quarantine.status();
        };

        loop {
            let status = quarantine.status();
            if status != LinuxQemuAttemptProcessQuarantineStatus::Running {
                return status;
            }
            let Some(now) = Duration::try_from(clock_gettime(ClockId::Monotonic)).ok() else {
                return status;
            };
            if now >= deadline {
                return status;
            }
            thread::sleep(CGROUP_KILL_INTERVAL.min(deadline.saturating_sub(now)));
        }
    }

    struct FakeWork {
        attempts: Arc<AtomicUsize>,
        completed: Arc<AtomicBool>,
        fail_once: bool,
    }

    struct PanickingWork {
        dropped: Arc<AtomicBool>,
    }

    impl QuarantineWork for PanickingWork {
        type Error = ();

        fn reap_and_release(&mut self) -> Result<(), Self::Error> {
            panic!("forced process-quarantine invariant panic");
        }
    }

    impl Drop for PanickingWork {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::Release);
        }
    }

    impl QuarantineWork for FakeWork {
        type Error = ();

        fn reap_and_release(&mut self) -> Result<(), Self::Error> {
            self.attempts.fetch_add(1, Ordering::AcqRel);
            if self.fail_once {
                self.fail_once = false;
                return Err(());
            }
            self.completed.store(true, Ordering::Release);
            Ok(())
        }
    }

    #[test]
    fn dropped_handle_cannot_drop_detached_cleanup_work() -> Result<(), io::Error> {
        let attempts = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicBool::new(false));
        let quarantine = start_worker(FakeWork {
            attempts: Arc::clone(&attempts),
            completed: Arc::clone(&completed),
            fail_once: true,
        })
        .map_err(|(source, _)| source)?;
        drop(quarantine);

        for _ in 0..100 {
            if completed.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(completed.load(Ordering::Acquire));
        assert_eq!(attempts.load(Ordering::Acquire), 2);
        Ok(())
    }

    #[test]
    fn invariant_panic_parks_without_dropping_authority() -> Result<(), io::Error> {
        let dropped = Arc::new(AtomicBool::new(false));
        let quarantine = start_worker(PanickingWork {
            dropped: Arc::clone(&dropped),
        })
        .map_err(|(source, _)| source)?;

        assert_eq!(
            wait_for_status(&quarantine, Duration::from_secs(1)),
            LinuxQemuAttemptProcessQuarantineStatus::ParkedWithAuthority
        );
        drop(quarantine);
        thread::sleep(Duration::from_millis(20));
        assert!(!dropped.load(Ordering::Acquire));
        Ok(())
    }
}
