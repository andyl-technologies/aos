//! Cross-worker wait registry and deadlock-cycle detection for parallel forcing.
//!
//! When K workers force overlapping thunks in one shared demand graph, a
//! blocked worker must never park behind a chain of owners that leads back to
//! itself: that is a cross-worker evaluation cycle, and parking would deadlock
//! where serial evaluation reports infinite recursion. This module owns the
//! shared registry that makes that decision sound.
//!
//! # Protocol
//!
//! The registry is a single mutex-guarded map from worker id to the one wait
//! edge that worker is currently parked on:
//!
//! ```text
//! waiter worker -> (awaited cell key, owner worker of that cell)
//! ```
//!
//! Two operations share the mutex as their linearization point:
//!
//! - **Registration** ([`ParallelForceCycleRegistry::register_parked_waiter`]):
//!   under the lock, the waiter re-reads the awaited cell's state word. If the
//!   cell is still live-claimed by a foreign owner, the waiter walks the owner
//!   chain through the registered wait edges. Reaching itself is a deadlock
//!   cycle and the waiter must raise the serial infinite-recursion error
//!   instead of parking; otherwise the edge is inserted and the waiter may
//!   park.
//! - **Terminal publication** ([`ParallelForceCycleRegistry::publish_purged`]):
//!   under the same lock, the publisher first purges every wait edge that
//!   references the cell being published and then runs the terminal
//!   state-word transition *while still holding the lock*.
//!
//! Because the terminal transition happens inside the registry critical
//! section, a wait edge observed under the lock always references a cell that
//! is still live-claimed: the edge was inserted after a locked non-terminal
//! state check, and any terminal publication since then would have purged it
//! first. Owners of live claims never change (a claimed state word only moves
//! to a terminal state), so every hop of the owner walk is a genuine "worker X
//! is blocked on a cell owned by worker Y" edge at the instant of the walk. A
//! cycle of such edges is a true deadlock, never a stale-read artifact, so
//! raising infinite recursion is exact - and every real deadlock is caught,
//! because its final participant performs the walk while all other
//! participants' edges are registered and live.
//!
//! Waiters additionally deregister themselves after waking; that removal is
//! idempotent with the publisher's purge and only tightens the map.
//!
//! # Lock ordering
//!
//! The registry mutex may be acquired while holding a wait cell's waiter
//! mutex (waiter registration happens inside the parked wait path). The
//! reverse nesting never occurs: publishers release the registry lock before
//! notifying waiters. There is therefore a single lock order
//! `waiter mutex -> registry mutex` and no deadlock between the two.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, PoisonError},
};

use super::thunk_cas::{ParallelThunkState, ParallelThunkStateError, ParallelThunkWorkerId};

/// One registered wait edge: the cell a worker is parked on and its owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParallelForceWaitEdge {
    /// Identity key of the awaited wait cell (its stable address).
    cell: usize,
    /// The worker that owns the live claim on the awaited cell.
    owner: ParallelThunkWorkerId,
}

/// The registration decision for a waiter about to park on a foreign claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParallelForceWaitRegistration {
    /// The wait edge was recorded; the waiter may park on the cell.
    Registered,
    /// The cell reached a terminal state; the waiter must re-read it instead
    /// of parking. No edge was recorded.
    Terminal,
    /// The cell is no longer claimed; the waiter should retry its claim. No
    /// edge was recorded.
    Unclaimed,
    /// The awaited cell is owned by the waiter itself (direct re-entry). No
    /// edge was recorded.
    SelfOwned {
        /// The owner of the recursive claim (the waiter).
        owner: ParallelThunkWorkerId,
    },
    /// Parking would close a cross-worker ownership cycle back to the waiter.
    /// No edge was recorded; the waiter must raise infinite recursion.
    Cycle {
        /// The owner of the directly awaited cell.
        owner: ParallelThunkWorkerId,
    },
}

/// A shared cross-worker wait registry for parallel thunk forcing.
///
/// One registry instance must be shared by every worker (every parallel thunk
/// cell) of one shared demand graph; the cycle walk is only meaningful over
/// edges recorded in the same registry. See the module docs for the protocol
/// and its soundness argument.
#[derive(Debug, Default)]
pub struct ParallelForceCycleRegistry {
    waits: Mutex<HashMap<u64, ParallelForceWaitEdge>>,
}

impl ParallelForceCycleRegistry {
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Decides whether `waiter` may park on the cell identified by `cell`.
    ///
    /// `state` must re-read the awaited cell's state word and is invoked under
    /// the registry lock, which is what makes the returned decision race-free
    /// against concurrent terminal publications (see the module docs). On
    /// [`ParallelForceWaitRegistration::Registered`] the wait edge has been
    /// inserted and the caller must eventually remove it with
    /// [`Self::deregister_waiter`] after waking.
    ///
    /// # Errors
    ///
    /// Returns [`ParallelThunkStateError`] if `state` reports an unsupported
    /// state-word encoding.
    pub fn register_parked_waiter(
        &self,
        waiter: ParallelThunkWorkerId,
        cell: usize,
        state: impl FnOnce() -> Result<ParallelThunkState, ParallelThunkStateError>,
    ) -> Result<ParallelForceWaitRegistration, ParallelThunkStateError> {
        let mut waits = self.lock_waits();
        let owner = match state()? {
            ParallelThunkState::Forced | ParallelThunkState::Failed => {
                return Ok(ParallelForceWaitRegistration::Terminal);
            }
            ParallelThunkState::Suspended => {
                return Ok(ParallelForceWaitRegistration::Unclaimed);
            }
            ParallelThunkState::Pending { owner } | ParallelThunkState::Awaited { owner } => owner,
        };
        if owner == waiter {
            return Ok(ParallelForceWaitRegistration::SelfOwned { owner });
        }
        if owner_chain_reaches(&waits, owner, waiter) {
            return Ok(ParallelForceWaitRegistration::Cycle { owner });
        }
        waits.insert(waiter.get(), ParallelForceWaitEdge { cell, owner });
        Ok(ParallelForceWaitRegistration::Registered)
    }

    /// Removes `waiter`'s wait edge for `cell`, if it is still recorded.
    ///
    /// This is idempotent with the publisher-side purge performed by
    /// [`Self::publish_purged`]: an edge already removed by a terminal
    /// publication is simply absent. An edge for a different cell (from a
    /// later wait) is left untouched.
    pub fn deregister_waiter(&self, waiter: ParallelThunkWorkerId, cell: usize) {
        let mut waits = self.lock_waits();
        if waits.get(&waiter.get()).is_some_and(|edge| edge.cell == cell) {
            waits.remove(&waiter.get());
        }
    }

    /// Purges every wait edge referencing `cell`, then runs `publish` under
    /// the registry lock.
    ///
    /// `publish` must perform the terminal state-word transition for `cell`.
    /// Running it inside the critical section is what upholds the registry
    /// invariant that recorded edges always reference live claims; see the
    /// module docs.
    pub fn publish_purged<R>(&self, cell: usize, publish: impl FnOnce() -> R) -> R {
        let mut waits = self.lock_waits();
        waits.retain(|_, edge| edge.cell != cell);
        publish()
    }

    /// Returns the number of currently recorded wait edges.
    ///
    /// This is a diagnostics/test accessor; the count is naturally racy
    /// outside the registry lock.
    pub fn recorded_waits(&self) -> usize {
        self.lock_waits().len()
    }

    fn lock_waits(&self) -> MutexGuard<'_, HashMap<u64, ParallelForceWaitEdge>> {
        // Terminal publication and waiter wakeup must keep working after a
        // panic while the lock was held; the map only carries advisory wait
        // edges, and recovering the lock can at worst leave a stale edge that
        // the next purge or deregistration removes.
        self.waits.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Walks the owner chain from `start` through recorded wait edges and returns
/// whether it reaches `target`.
///
/// Each worker has at most one outgoing wait edge, so the walk is a simple
/// functional-graph traversal. Chains may close into cycles that do not
/// involve `target` (a deadlock among other workers, detected by its own
/// participants); the hop bound guarantees termination in that case.
fn owner_chain_reaches(
    waits: &HashMap<u64, ParallelForceWaitEdge>,
    start: ParallelThunkWorkerId,
    target: ParallelThunkWorkerId,
) -> bool {
    let mut current = start;
    // One hop per recorded edge is the longest possible simple chain.
    for _ in 0..=waits.len() {
        if current == target {
            return true;
        }
        match waits.get(&current.get()) {
            Some(edge) => current = edge.owner,
            None => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker(raw: u64) -> ParallelThunkWorkerId {
        ParallelThunkWorkerId::new(raw).expect("valid worker id")
    }

    fn live_state(owner: ParallelThunkWorkerId) -> ParallelThunkState {
        ParallelThunkState::Pending { owner }
    }

    #[test]
    fn registers_wait_edge_for_live_foreign_claim() {
        let registry = ParallelForceCycleRegistry::new();

        let registration = registry
            .register_parked_waiter(worker(1), 0x10, || Ok(live_state(worker(2))))
            .expect("state decodes");

        assert_eq!(registration, ParallelForceWaitRegistration::Registered);
        assert_eq!(registry.recorded_waits(), 1);
    }

    #[test]
    fn terminal_and_unclaimed_states_do_not_register() {
        let registry = ParallelForceCycleRegistry::new();

        assert_eq!(
            registry
                .register_parked_waiter(worker(1), 0x10, || Ok(ParallelThunkState::Forced))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Terminal
        );
        assert_eq!(
            registry
                .register_parked_waiter(worker(1), 0x10, || Ok(ParallelThunkState::Failed))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Terminal
        );
        assert_eq!(
            registry
                .register_parked_waiter(worker(1), 0x10, || Ok(ParallelThunkState::Suspended))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Unclaimed
        );
        assert_eq!(registry.recorded_waits(), 0);
    }

    #[test]
    fn self_owned_claim_is_reported_without_an_edge() {
        let registry = ParallelForceCycleRegistry::new();

        let registration = registry
            .register_parked_waiter(worker(1), 0x10, || Ok(live_state(worker(1))))
            .expect("state decodes");

        assert_eq!(
            registration,
            ParallelForceWaitRegistration::SelfOwned { owner: worker(1) }
        );
        assert_eq!(registry.recorded_waits(), 0);
    }

    #[test]
    fn two_worker_cycle_is_detected_by_the_second_waiter() {
        let registry = ParallelForceCycleRegistry::new();
        // Worker 1 parks on a cell owned by worker 2.
        assert_eq!(
            registry
                .register_parked_waiter(worker(1), 0xa, || Ok(live_state(worker(2))))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Registered
        );

        // Worker 2 tries to park on a cell owned by worker 1: cycle.
        let registration = registry
            .register_parked_waiter(worker(2), 0xb, || Ok(live_state(worker(1))))
            .expect("state decodes");

        assert_eq!(
            registration,
            ParallelForceWaitRegistration::Cycle { owner: worker(1) }
        );
        assert_eq!(registry.recorded_waits(), 1);
    }

    #[test]
    fn three_worker_ring_cycle_is_detected_by_the_last_waiter() {
        let registry = ParallelForceCycleRegistry::new();
        assert_eq!(
            registry
                .register_parked_waiter(worker(1), 0xa, || Ok(live_state(worker(2))))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Registered
        );
        assert_eq!(
            registry
                .register_parked_waiter(worker(2), 0xb, || Ok(live_state(worker(3))))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Registered
        );

        let registration = registry
            .register_parked_waiter(worker(3), 0xc, || Ok(live_state(worker(1))))
            .expect("state decodes");

        assert_eq!(
            registration,
            ParallelForceWaitRegistration::Cycle { owner: worker(1) }
        );
    }

    #[test]
    fn foreign_cycle_not_involving_the_waiter_terminates_and_parks() {
        let registry = ParallelForceCycleRegistry::new();
        // Workers 2 and 3 wait on each other (their own participants would
        // have detected this; the map state is still reachable transiently).
        assert_eq!(
            registry
                .register_parked_waiter(worker(2), 0xa, || Ok(live_state(worker(3))))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Registered
        );
        registry
            .lock_waits()
            .insert(3, ParallelForceWaitEdge { cell: 0xb, owner: worker(2) });

        // Worker 1 waits into the foreign 2 <-> 3 ring: the walk terminates
        // without reaching worker 1, so worker 1 may park.
        let registration = registry
            .register_parked_waiter(worker(1), 0xc, || Ok(live_state(worker(2))))
            .expect("state decodes");

        assert_eq!(registration, ParallelForceWaitRegistration::Registered);
    }

    #[test]
    fn publish_purges_edges_for_the_published_cell_only() {
        let registry = ParallelForceCycleRegistry::new();
        assert_eq!(
            registry
                .register_parked_waiter(worker(1), 0xa, || Ok(live_state(worker(2))))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Registered
        );
        assert_eq!(
            registry
                .register_parked_waiter(worker(3), 0xb, || Ok(live_state(worker(2))))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Registered
        );

        let published = registry.publish_purged(0xa, || 7);

        assert_eq!(published, 7);
        assert_eq!(registry.recorded_waits(), 1);
    }

    #[test]
    fn deregister_removes_only_the_matching_cell_edge() {
        let registry = ParallelForceCycleRegistry::new();
        assert_eq!(
            registry
                .register_parked_waiter(worker(1), 0xa, || Ok(live_state(worker(2))))
                .expect("state decodes"),
            ParallelForceWaitRegistration::Registered
        );

        // A stale deregistration for a different cell leaves the edge alone.
        registry.deregister_waiter(worker(1), 0xb);
        assert_eq!(registry.recorded_waits(), 1);

        registry.deregister_waiter(worker(1), 0xa);
        assert_eq!(registry.recorded_waits(), 0);

        // Idempotent after the edge is gone.
        registry.deregister_waiter(worker(1), 0xa);
        assert_eq!(registry.recorded_waits(), 0);
    }
}
