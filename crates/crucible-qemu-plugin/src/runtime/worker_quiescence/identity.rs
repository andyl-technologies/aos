//! Retains actual worker incarnations through private native borrower snapshots.
// SPDX-License-Identifier: GPL-2.0-or-later

use super::*;
use crate::ram_error::RamError;

impl LiveWorkerQuiescence {
    /// Registers only the calling actor, before its first receive or operation.
    pub(in crate::runtime) fn register_current(
        self: &Arc<Self>,
        worker: u64,
    ) -> Result<WorkerIdentityGuard, RamError> {
        // SAFETY: gettid takes no pointers and identifies this actual actor.
        let thread_id = unsafe { libc::syscall(libc::SYS_gettid) };
        let thread_id = u64::try_from(thread_id)
            .map_err(|_| RamError::Invariant("invalid plugin worker thread identity"))?;
        self.register_identity(worker, u64::from(std::process::id()), thread_id)
    }

    fn register_identity(
        self: &Arc<Self>,
        worker: u64,
        process_id: u64,
        thread_id: u64,
    ) -> Result<WorkerIdentityGuard, RamError> {
        let mut state = self.lock_state();
        if let Some(source) = &state.failure {
            return Err(source.clone());
        }
        let index = worker.trailing_zeros() as usize;
        if !worker.is_power_of_two()
            || self.worker_mask & worker == 0
            || index >= state.thread_ids.len()
            || process_id != state.process_id
            || process_id != u64::from(std::process::id())
            || thread_id == 0
            || state.thread_ids[index] != 0
            || state.thread_ids.contains(&thread_id)
        {
            let error = RamError::Invariant("plugin worker incarnation is invalid or repeated");
            state.failure = Some(error.clone());
            return Err(error);
        }
        let generation = state.membership_generation.checked_add(1).ok_or_else(|| {
            let error = RamError::Invariant("plugin worker membership generation exhausted");
            state.failure = Some(error.clone());
            error
        })?;
        state.membership_generation = generation;
        state.thread_ids[index] = thread_id;
        drop(state);
        self.released.notify_all();

        Ok(WorkerIdentityGuard {
            workers: Arc::clone(self),
            process_id,
            thread_id,
            index,
        })
    }

    /// Refuses sticky membership failure before exporting a private snapshot.
    pub(in crate::runtime) fn identity_snapshot(
        &self,
    ) -> Result<WorkerQuiescenceSnapshot, RamError> {
        let state = self.lock_state();
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        let snapshot = self.snapshot_locked(&state);
        Ok(snapshot)
    }

    pub(super) fn identities_complete(&self, snapshot: &WorkerQuiescenceSnapshot) -> bool {
        if snapshot.process_id != u64::from(std::process::id())
            || snapshot.membership_generation == 0
        {
            return false;
        }
        for (index, thread_id) in snapshot.thread_ids.iter().enumerate() {
            if (*thread_id != 0) != (self.worker_mask & (1 << index) != 0)
                || (*thread_id != 0 && snapshot.thread_ids[..index].contains(thread_id))
            {
                return false;
            }
        }
        true
    }

    /// Completes initial actor publication under the already running Setup token.
    pub(in crate::runtime) fn wait_initial_ready(
        &self,
        mut wait_slice: impl FnMut() -> Result<std::time::Duration, RamError>,
    ) -> Result<(), RamError> {
        loop {
            let slice = wait_slice()?;
            let state = self.lock_state();
            if let Some(error) = &state.failure {
                return Err(error.clone());
            }
            let snapshot = self.snapshot_locked(&state);
            let ready = self.identities_complete(&snapshot)
                && snapshot.parked_mask == snapshot.worker_mask
                && snapshot.pending_mask == 0
                && snapshot.operations_in_flight == 0;
            drop(state);
            if ready {
                return Ok(());
            }
            std::thread::sleep(slice.min(std::time::Duration::from_millis(10)));
        }
    }
}

/// Clears only this registered process/thread/role incarnation on actual exit.
pub(in crate::runtime) struct WorkerIdentityGuard {
    workers: Arc<LiveWorkerQuiescence>,
    process_id: u64,
    thread_id: u64,
    index: usize,
}

impl Drop for WorkerIdentityGuard {
    fn drop(&mut self) {
        if self.process_id != u64::from(std::process::id()) {
            return;
        }
        let mut state = self.workers.lock_state();
        if state.process_id != self.process_id || state.thread_ids[self.index] != self.thread_id {
            state.failure = Some(RamError::Invariant(
                "plugin worker exit lost its incarnation",
            ));
            return;
        }
        state.thread_ids[self.index] = 0;
        match state.membership_generation.checked_add(1) {
            Some(generation) => state.membership_generation = generation,
            None => {
                state.failure = Some(RamError::Invariant(
                    "plugin worker membership generation exhausted",
                ))
            }
        }
        if state.held {
            state.failure = Some(RamError::Invariant(
                "plugin worker exited under a retained barrier",
            ));
        }
        drop(state);
        self.workers.released.notify_all();
    }
}

#[cfg(test)]
mod tests;
