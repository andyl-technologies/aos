//! In-process worker admission for the closed Storage Repair drain.
//!
//! Closing admission precedes the final cgroup quiescence scan. A dispatch
//! lease only accounts for work in this broker process; the scan must still
//! kill and prove absent workers inherited from an interrupted process.

use std::sync::{Arc, Mutex};

use super::StorageRuntimeError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DrainPhase {
    Open,
    TerminalHeld,
    Draining,
    Quiesced,
}

struct DrainState {
    phase: DrainPhase,
    in_flight: usize,
}

/// Serializes new worker admission against a one-way Repair drain.
#[derive(Clone)]
pub(super) struct RepairWorkerDispatchGate {
    state: Arc<Mutex<DrainState>>,
}

/// Retains in-process custody until the worker-bearing call returns.
pub(super) struct WorkerDispatchLease {
    state: Arc<Mutex<DrainState>>,
}

impl RepairWorkerDispatchGate {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(DrainState {
                phase: DrainPhase::Open,
                in_flight: 0,
            })),
        }
    }

    pub(super) fn is_open(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|state| state.phase == DrainPhase::Open)
    }

    pub(super) fn enter(&self) -> Result<WorkerDispatchLease, ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.phase != DrainPhase::Open {
            return Err(());
        }
        state.in_flight = state.in_flight.checked_add(1).ok_or(())?;
        Ok(WorkerDispatchLease {
            state: Arc::clone(&self.state),
        })
    }

    /// Excludes ordinary dispatch until the actual terminal owner settles.
    pub(super) fn begin_terminal_hold(&self) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if !matches!(state.phase, DrainPhase::Open | DrainPhase::TerminalHeld)
            || state.in_flight != 0
        {
            return Err(());
        }
        state.phase = DrainPhase::TerminalHeld;
        Ok(())
    }

    /// Reopens only after the caller has durably settled the exact owner hold.
    pub(super) fn settle_terminal_hold(&self) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.phase != DrainPhase::TerminalHeld || state.in_flight != 0 {
            return Err(());
        }
        state.phase = DrainPhase::Open;
        Ok(())
    }

    /// Closes admission before checking whether existing calls have returned.
    pub(super) fn begin_drain(&self) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.phase == DrainPhase::Open {
            state.phase = DrainPhase::Draining;
        }
        if state.phase != DrainPhase::Draining || state.in_flight != 0 {
            return Err(());
        }
        Ok(())
    }

    /// Records success only after both reserved worker scopes scan empty.
    pub(super) fn finish_drain(&self) -> Result<(), ()> {
        let mut state = self.state.lock().map_err(|_| ())?;
        if state.phase != DrainPhase::Draining || state.in_flight != 0 {
            return Err(());
        }
        state.phase = DrainPhase::Quiesced;
        Ok(())
    }
}

impl Drop for WorkerDispatchLease {
    fn drop(&mut self) {
        // Poisoning leaves the gate permanently closed; it cannot authorize a
        // drain even if this counter is not updated.
        if let Ok(mut state) = self.state.lock() {
            state.in_flight -= 1;
        }
    }
}

/// Closes dispatch first, then proves both reserved systemd worker scopes empty.
pub(super) fn close_and_drain_worker_scopes(
    gate: &RepairWorkerDispatchGate,
    quiesce_pin_and_zfs: impl FnOnce() -> Result<(), StorageRuntimeError>,
    quiesce_guest_root: impl FnOnce() -> Result<(), StorageRuntimeError>,
) -> Result<(), StorageRuntimeError> {
    gate.begin_drain()
        .map_err(|_| StorageRuntimeError::Recovery)?;
    quiesce_pin_and_zfs()?;
    quiesce_guest_root()?;
    gate.finish_drain()
        .map_err(|_| StorageRuntimeError::Recovery)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::{RepairWorkerDispatchGate, close_and_drain_worker_scopes};
    use crate::StorageRuntimeError;

    #[test]
    fn terminal_hold_excludes_all_new_dispatch_and_is_not_a_repair_drain() {
        let gate = RepairWorkerDispatchGate::new();

        gate.begin_terminal_hold().unwrap();

        assert!(!gate.is_open());
        assert!(gate.enter().is_err());
        assert!(gate.begin_drain().is_err());
        assert!(gate.finish_drain().is_err());
        gate.begin_terminal_hold().unwrap();
        assert!(!gate.is_open());
    }

    #[test]
    fn an_existing_dispatch_prevents_terminal_hold_until_its_lease_returns() {
        let gate = RepairWorkerDispatchGate::new();
        let lease = gate.enter().unwrap();

        assert!(gate.begin_terminal_hold().is_err());
        drop(lease);
        gate.begin_terminal_hold().unwrap();

        assert!(gate.enter().is_err());
        assert!(!gate.is_open());
    }

    #[test]
    fn dropping_one_gate_handle_does_not_release_an_unacknowledged_hold() {
        let gate = RepairWorkerDispatchGate::new();
        let retained = gate.clone();
        gate.begin_terminal_hold().unwrap();

        drop(gate);

        assert!(!retained.is_open());
        assert!(retained.enter().is_err());
        retained.settle_terminal_hold().unwrap();
        assert!(retained.is_open());
        assert!(retained.enter().is_ok());
    }

    #[test]
    fn terminal_settlement_never_opens_a_generic_drained_or_quiesced_gate() {
        let gate = RepairWorkerDispatchGate::new();
        assert!(gate.settle_terminal_hold().is_err());

        gate.begin_drain().unwrap();
        assert!(gate.settle_terminal_hold().is_err());
        gate.finish_drain().unwrap();

        assert!(gate.settle_terminal_hold().is_err());
        assert!(gate.begin_terminal_hold().is_err());
        assert!(!gate.is_open());
    }

    #[test]
    fn drain_closes_dispatch_before_an_existing_worker_returns() {
        let gate = RepairWorkerDispatchGate::new();
        let worker_entered = Arc::new(Barrier::new(2));
        let worker_release = Arc::new(Barrier::new(2));
        let worker_gate = gate.clone();
        let entered = Arc::clone(&worker_entered);
        let release = Arc::clone(&worker_release);
        let worker = thread::spawn(move || {
            let _lease = worker_gate.enter().unwrap();
            entered.wait();
            release.wait();
        });

        worker_entered.wait();
        assert!(
            close_and_drain_worker_scopes(
                &gate,
                || panic!("the cgroup scan must wait for in-process custody"),
                || panic!("the publisher scan must wait for in-process custody"),
            )
            .is_err()
        );
        assert!(!gate.is_open());
        assert!(gate.enter().is_err());
        assert!(gate.finish_drain().is_err());

        worker_release.wait();
        worker.join().unwrap();
        close_and_drain_worker_scopes(&gate, || Ok(()), || Ok(())).unwrap();
        assert!(gate.enter().is_err());
    }

    #[test]
    fn failed_final_scan_never_reopens_admission() {
        let gate = RepairWorkerDispatchGate::new();
        let result = close_and_drain_worker_scopes(
            &gate,
            || {
                assert!(!gate.is_open());
                Err(StorageRuntimeError::Recovery)
            },
            || panic!("guest-root scan must not follow a failed pin/ZFS scan"),
        );
        assert!(result.is_err());
        assert!(gate.enter().is_err());
        assert!(!gate.is_open());
        close_and_drain_worker_scopes(&gate, || Ok(()), || Ok(())).unwrap();
        assert!(gate.enter().is_err());
    }

    #[test]
    fn guest_root_scan_failure_keeps_dispatch_closed() {
        let gate = RepairWorkerDispatchGate::new();
        let result = close_and_drain_worker_scopes(
            &gate,
            || {
                assert!(gate.enter().is_err());
                Ok(())
            },
            || Err(StorageRuntimeError::Recovery),
        );
        assert!(result.is_err());
        assert!(gate.enter().is_err());
    }

    #[test]
    fn both_scopes_scan_in_order_under_closed_admission() {
        let gate = RepairWorkerDispatchGate::new();
        let scans = Cell::new(0);
        close_and_drain_worker_scopes(
            &gate,
            || {
                assert!(gate.enter().is_err());
                scans.set(1);
                Ok(())
            },
            || {
                assert!(gate.enter().is_err());
                assert_eq!(scans.get(), 1);
                scans.set(2);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(scans.get(), 2);
        assert!(gate.enter().is_err());
    }
}
