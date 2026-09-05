//! Aggregate target-resource ownership for one hot-fork child world.
//!
//! A campaign branch owns one attempt-wide CPU, memory, writable-storage,
//! cancellation, and execution-quantum contract even when its World contains
//! several QEMU children. This module keeps that guard indivisible while
//! issuing one linear node target for each child. Per-node reconciliation may
//! attest that its exact child is gone, but only the aggregate owner can release
//! the underlying attempt guard after every issued target has finished.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex};

use crucible_api::ProductionVmNodeGeneration;
use crucible_campaign::AttemptResourceLimits;
use crucible_qemu::QemuVmRealizationError;

use crate::{
    ExecutionCancellation, MAX_QEMU_ATTEMPT_GENERATION_NODES, QemuAttemptOperationalBoundary,
    QemuAttemptResourceGuard,
};

struct QemuHotForkWorldResourceState<G>
where
    G: QemuAttemptResourceGuard,
{
    guard: G,
    maximum_nodes: usize,
    issued: BTreeSet<ProductionVmNodeGeneration>,
    released: BTreeSet<ProductionVmNodeGeneration>,
    terminal: bool,
    terminal_failure: Option<String>,
}

/// Indivisible attempt-resource owner shared by every child in one forked World.
#[must_use = "finish the complete hot-fork world owner or transfer it to quarantine"]
pub struct QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
}

impl<G> fmt::Debug for QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut output = formatter.debug_struct("QemuHotForkWorldResourceOwner");
        output.field("resources", &self.resources);
        match self.state.lock() {
            Ok(state) => output
                .field("maximum_nodes", &state.maximum_nodes)
                .field("issued", &state.issued.len())
                .field("released", &state.released.len())
                .field("terminal", &state.terminal),
            Err(_) => output.field("state", &"poisoned"),
        };
        output.finish_non_exhaustive()
    }
}

impl<G> QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    /// Seals one installed attempt guard behind a bounded World node registry.
    ///
    /// # Errors
    ///
    /// Returns an executor error and quarantines `guard` when `maximum_nodes`
    /// is zero or exceeds [`MAX_QEMU_ATTEMPT_GENERATION_NODES`].
    pub fn new(mut guard: G, maximum_nodes: usize) -> Result<Self, QemuVmRealizationError> {
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            guard.quarantine();
            return Err(world_resource_error(format!(
                "hot-fork world node bound {maximum_nodes} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
            )));
        }
        let resources = guard.resource_limits();
        let cancellation = guard.cancellation().clone();
        Ok(Self {
            state: Arc::new(Mutex::new(QemuHotForkWorldResourceState {
                guard,
                maximum_nodes,
                issued: BTreeSet::new(),
                released: BTreeSet::new(),
                terminal: false,
                terminal_failure: None,
            })),
            resources,
            cancellation,
        })
    }

    /// Returns the exact attempt-wide hard-resource basis.
    #[must_use]
    pub const fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    /// Returns the exact process-local cancellation incarnation.
    #[must_use]
    pub const fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    /// Reserves one exact child generation before its QEMU fork transaction.
    ///
    /// A caller must either install the returned target into the successful
    /// child reconciliation owner or roll it back after an explicit pre-fork
    /// rejection. Dropping an unfinished target quarantines the complete World.
    ///
    /// # Errors
    ///
    /// Returns an executor error after terminal cleanup, registry poison,
    /// duplicate generation, or distinct-node bound exhaustion.
    pub(crate) fn reserve_node(
        &mut self,
        identity: ProductionVmNodeGeneration,
    ) -> Result<QemuHotForkWorldNodeTarget<G>, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal {
            return Err(world_resource_error(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world resource owner is terminal"),
            ));
        }
        if state
            .issued
            .iter()
            .any(|issued| issued.node() == identity.node())
        {
            return Err(world_resource_error(format!(
                "hot-fork world already reserved node `{}`",
                identity.node().name
            )));
        }
        if state.issued.len() >= state.maximum_nodes {
            return Err(world_resource_error(format!(
                "hot-fork world node bound {} is exhausted",
                state.maximum_nodes
            )));
        }
        state.issued.insert(identity.clone());
        drop(state);
        Ok(QemuHotForkWorldNodeTarget {
            state: Arc::clone(&self.state),
            identity,
            resources: self.resources,
            cancellation: self.cancellation.clone(),
            released: false,
        })
    }

    /// Runs one launch-only operation against the still-indivisible guard.
    ///
    /// # Errors
    ///
    /// Returns an executor error after terminal cleanup or registry poison.
    pub(crate) fn with_guard_mut<T>(
        &mut self,
        operation: impl FnOnce(&mut G) -> T,
    ) -> Result<T, QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal {
            return Err(world_resource_error(
                state
                    .terminal_failure
                    .as_deref()
                    .unwrap_or("hot-fork world resource owner is terminal"),
            ));
        }
        Ok(operation(&mut state.guard))
    }

    /// Releases aggregate enforcement after every exact child target finished.
    ///
    /// The method is idempotent after success. An incomplete target set
    /// quarantines the underlying guard rather than claiming resource release.
    ///
    /// # Errors
    ///
    /// Returns an executor error when a target remains live, the registry is
    /// poisoned, or the underlying guard cannot attest final release.
    pub fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal {
            return state
                .terminal_failure
                .as_ref()
                .map_or(Ok(()), |message| Err(world_resource_error(message.clone())));
        }
        if state.issued != state.released {
            let message =
                String::from("hot-fork world aggregate release has an unfinished child target");
            state.guard.quarantine();
            state.terminal = true;
            state.terminal_failure = Some(message.clone());
            return Err(world_resource_error(message));
        }
        let result = state.guard.finish();
        state.terminal = true;
        if let Err(error) = &result {
            state.terminal_failure = Some(error.to_string());
        }
        result
    }

    /// Transfers the complete aggregate guard to fail-closed quarantine.
    pub fn quarantine(&mut self) {
        quarantine_world_state(&self.state);
    }
}

impl<G> Drop for QemuHotForkWorldResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        quarantine_world_state(&self.state);
    }
}

/// Linear target-resource share for one exact child generation.
///
/// This value can check and charge the shared attempt contract, but it cannot
/// release aggregate enforcement. Its [`QemuAttemptResourceGuard::finish`]
/// implementation records only that this exact child completed target cleanup;
/// the owning [`QemuHotForkWorldResourceOwner`] performs final release.
#[must_use = "finish the hot-fork node target only after exact child reap"]
pub struct QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    state: Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    identity: ProductionVmNodeGeneration,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    released: bool,
}

impl<G> fmt::Debug for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuHotForkWorldNodeTarget")
            .field("identity", &self.identity)
            .field("released", &self.released)
            .finish_non_exhaustive()
    }
}

impl<G> QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    /// Returns the exact node-generation reservation represented by this share.
    #[must_use]
    pub const fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    pub(crate) fn abort_without_child(mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.terminal
            || state.released.contains(&self.identity)
            || !state.issued.remove(&self.identity)
        {
            return Err(world_resource_error(
                "hot-fork world no-child rollback lost its exact reservation",
            ));
        }
        self.released = true;
        Ok(())
    }

    fn finish_node(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.released {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if state.released.contains(&self.identity) {
            self.released = true;
            return Ok(());
        }
        if state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "hot-fork node target is not active in its aggregate owner",
            ));
        }
        state.released.insert(self.identity.clone());
        self.released = true;
        Ok(())
    }
}

impl<G> QemuAttemptOperationalBoundary for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.released || state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "hot-fork node target is not operational",
            ));
        }
        state.guard.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| world_resource_error("hot-fork world resource registry is poisoned"))?;
        if self.released || state.terminal || !state.issued.contains(&self.identity) {
            return Err(world_resource_error(
                "hot-fork node target is not operational",
            ));
        }
        state.guard.charge_execution_quantum()
    }
}

impl<G> QemuAttemptResourceGuard for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        self.finish_node()
    }

    fn quarantine(&mut self) {
        if !self.released {
            quarantine_world_state(&self.state);
            self.released = true;
        }
    }
}

impl<G> Drop for QemuHotForkWorldNodeTarget<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        if !self.released && !world_node_is_released(&self.state, &self.identity) {
            quarantine_world_state(&self.state);
        }
    }
}

fn world_node_is_released<G>(
    state: &Arc<Mutex<QemuHotForkWorldResourceState<G>>>,
    identity: &ProductionVmNodeGeneration,
) -> bool
where
    G: QemuAttemptResourceGuard,
{
    match state.lock() {
        Ok(state) => state.released.contains(identity),
        Err(_) => false,
    }
}

fn quarantine_world_state<G>(state: &Arc<Mutex<QemuHotForkWorldResourceState<G>>>)
where
    G: QemuAttemptResourceGuard,
{
    match state.lock() {
        Ok(mut state) => {
            if !state.terminal {
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "hot-fork world resources were transferred to quarantine",
                ));
            }
        }
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            if !state.terminal {
                state.guard.quarantine();
                state.terminal = true;
                state.terminal_failure = Some(String::from(
                    "hot-fork world resource registry was poisoned and quarantined",
                ));
            }
        }
    }
}

fn world_resource_error(message: impl Into<String>) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "manage aggregate hot-fork world resources",
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture construction and expected success must fail the test on error.
    #![allow(clippy::expect_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use crucible::NodeId;

    use super::*;
    use crate::QemuExecutionQuantumCounter;

    #[derive(Debug)]
    struct FakeGuard {
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
        counter: QemuExecutionQuantumCounter,
        finishes: Arc<AtomicUsize>,
        quarantines: Arc<AtomicUsize>,
    }

    impl QemuAttemptOperationalBoundary for FakeGuard {
        fn resource_limits(&self) -> AttemptResourceLimits {
            self.resources
        }

        fn cancellation(&self) -> &ExecutionCancellation {
            &self.cancellation
        }

        fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
            Ok(())
        }

        fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
            self.counter.charge()
        }
    }

    impl QemuAttemptResourceGuard for FakeGuard {
        fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
            self.finishes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn quarantine(&mut self) {
            self.quarantines.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn resources() -> AttemptResourceLimits {
        AttemptResourceLimits::new(2, 1024, 1024, 2).expect("resource limits")
    }

    fn identity(name: &str, generation: u64) -> ProductionVmNodeGeneration {
        ProductionVmNodeGeneration::new(
            NodeId {
                name: name.to_owned(),
            },
            generation,
        )
        .expect("node generation")
    }

    fn guard(finishes: Arc<AtomicUsize>, quarantines: Arc<AtomicUsize>) -> FakeGuard {
        let resources = resources();
        FakeGuard {
            resources,
            cancellation: ExecutionCancellation::default(),
            counter: QemuExecutionQuantumCounter::new(resources),
            finishes,
            quarantines,
        }
    }

    #[test]
    fn aggregate_release_waits_for_every_exact_node_target() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            2,
        )
        .expect("world owner");
        let mut first = owner.reserve_node(identity("first", 4)).expect("first");
        let mut second = owner.reserve_node(identity("second", 9)).expect("second");

        first
            .charge_execution_quantum()
            .expect("shared quantum one");
        second
            .charge_execution_quantum()
            .expect("shared quantum two");
        assert!(second.charge_execution_quantum().is_err());
        QemuAttemptResourceGuard::finish(&mut first).expect("finish first");
        QemuAttemptResourceGuard::finish(&mut second).expect("finish second");
        owner.finish().expect("finish aggregate");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }

    #[test]
    fn unfinished_or_duplicate_node_fails_closed() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        let target = owner.reserve_node(identity("node", 3)).expect("node");
        assert!(owner.reserve_node(identity("node", 4)).is_err());
        assert!(owner.finish().is_err());
        drop(target);

        assert_eq!(finishes.load(Ordering::Acquire), 0);
        assert_eq!(quarantines.load(Ordering::Acquire), 1);
    }

    #[test]
    fn explicit_no_child_rollback_reopens_the_exact_slot() {
        let finishes = Arc::new(AtomicUsize::new(0));
        let quarantines = Arc::new(AtomicUsize::new(0));
        let mut owner = QemuHotForkWorldResourceOwner::new(
            guard(Arc::clone(&finishes), Arc::clone(&quarantines)),
            1,
        )
        .expect("world owner");
        owner
            .reserve_node(identity("node", 3))
            .expect("reserve")
            .abort_without_child()
            .expect("rollback");
        let mut retried = owner.reserve_node(identity("node", 3)).expect("retry");
        QemuAttemptResourceGuard::finish(&mut retried).expect("finish retry");
        owner.finish().expect("finish aggregate");

        assert_eq!(finishes.load(Ordering::Acquire), 1);
        assert_eq!(quarantines.load(Ordering::Acquire), 0);
    }
}
