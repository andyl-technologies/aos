//! Process resource ownership for one QEMU execution generation.

use super::*;

/// Attempt-wide guard owner with exact linear process-generation leases.
///
/// The owner seals one resource guard behind a bounded generation registry.
/// Each scheduler node may advance only to a strictly newer positive generation.
/// The live set retains at most the active generation and one staged successor,
/// matching the lifecycle's replace-before-reap transaction without permitting
/// an unbounded generation chain. Finished leases leave only one latest-
/// generation integer per scenario node. Dropping an unfinished lease poisons
/// aggregate release; dropping this owner transfers the underlying guard to
/// quarantine.
#[must_use = "finish the generation owner or transfer its guard to quarantine"]
pub struct QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    guard: G,
    generations: Arc<Mutex<QemuAttemptGenerationState>>,
    terminal: bool,
    terminal_failure: Option<String>,
}

impl<G> fmt::Debug for QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuAttemptGenerationResourceOwner")
            .field("guard", &self.guard)
            .field("terminal", &self.terminal)
            .field("terminal_failure", &self.terminal_failure)
            .finish_non_exhaustive()
    }
}

impl<G> QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    /// Seals one live attempt guard behind a bounded generation registry.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when `maximum_nodes` is zero
    /// or exceeds [`MAX_QEMU_ATTEMPT_GENERATION_NODES`]. The supplied guard is
    /// quarantined before rejection.
    pub fn new(mut guard: G, maximum_nodes: usize) -> Result<Self, LifecycleApiError> {
        if maximum_nodes == 0 || maximum_nodes > MAX_QEMU_ATTEMPT_GENERATION_NODES {
            guard.quarantine();
            return Err(generation_error(format!(
                "QEMU attempt generation-node bound {maximum_nodes} is outside 1..={MAX_QEMU_ATTEMPT_GENERATION_NODES}"
            )));
        }
        Ok(Self {
            guard,
            generations: Arc::new(Mutex::new(QemuAttemptGenerationState {
                maximum_nodes,
                latest: BTreeMap::new(),
                active: BTreeSet::new(),
                abandoned: false,
            })),
            terminal: false,
            terminal_failure: None,
        })
    }

    /// Registers one strictly newer node generation and returns its linear lease.
    ///
    /// Registration is failure-atomic. A new node is retained only when the
    /// fixed distinct-node bound has room, and a known node must advance beyond
    /// its last issued generation. The lease must be finished only after its
    /// exact QEMU child has been reaped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after terminal cleanup,
    /// registry poison, prior lease abandonment, node-bound exhaustion, or a
    /// duplicate/stale generation.
    pub fn register_generation(
        &mut self,
        identity: ProductionVmNodeGeneration,
    ) -> Result<QemuAttemptGenerationLease, LifecycleApiError> {
        if self.terminal {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        if state.abandoned {
            return Err(generation_error(
                "a QEMU attempt generation lease was abandoned",
            ));
        }
        let node = identity.node().clone();
        let previous_generation = state.latest.get(&node).copied();
        let active_for_node = state
            .active
            .iter()
            .filter(|active| active.node() == &node)
            .count();
        if active_for_node >= MAX_QEMU_ATTEMPT_GENERATIONS_PER_NODE {
            return Err(generation_error(format!(
                "QEMU node `{}` already retains the active and staged generation leases",
                node.name,
            )));
        }
        if let Some(latest) = state.latest.get(&node) {
            if identity.generation() <= *latest {
                return Err(generation_error(format!(
                    "QEMU node `{}` generation {} does not advance beyond {latest}",
                    node.name,
                    identity.generation()
                )));
            }
        } else if state.latest.len() >= state.maximum_nodes {
            return Err(generation_error(format!(
                "QEMU attempt generation-node bound {} is exhausted",
                state.maximum_nodes
            )));
        }
        if !state.active.insert(identity.clone()) {
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} is already active",
                node.name,
                identity.generation()
            )));
        }
        state.latest.insert(node, identity.generation());
        drop(state);
        Ok(QemuAttemptGenerationLease {
            identity,
            generations: Arc::clone(&self.generations),
            previous_generation,
            finished: false,
        })
    }

    /// Finishes the aggregate guard after every exact generation lease released.
    ///
    /// An abandoned or still-active lease causes immediate quarantine; aggregate
    /// CPU, memory, disk, and quantum ownership is never released from that
    /// state. The operation is idempotent after a successful finish.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when a lease remains active or
    /// abandoned, the registry is poisoned, or underlying guard cleanup fails.
    pub fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if self.terminal {
            return self
                .terminal_failure
                .as_ref()
                .map_or(Ok(()), |message| Err(generation_error(message.clone())));
        }
        let release_allowed = self
            .generations
            .lock()
            .map(|state| !state.abandoned && state.active.is_empty())
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"));
        match release_allowed {
            Ok(true) => {}
            Ok(false) => {
                let message = String::from(
                    "QEMU attempt aggregate release has an active or abandoned generation",
                );
                self.guard.quarantine();
                self.terminal = true;
                self.terminal_failure = Some(message.clone());
                return Err(generation_error(message));
            }
            Err(error) => {
                let message = error.to_string();
                self.guard.quarantine();
                self.terminal = true;
                self.terminal_failure = Some(message);
                return Err(error);
            }
        }
        let result = self.guard.finish();
        self.terminal = true;
        match result {
            Ok(()) => Ok(()),
            Err(error) => {
                let message = format!("finish QEMU attempt aggregate resources: {error}");
                self.terminal_failure = Some(message.clone());
                Err(generation_error(message))
            }
        }
    }

    /// Transfers the aggregate guard to quarantine without releasing resources.
    pub fn quarantine(&mut self) {
        if self.terminal {
            return;
        }
        self.guard.quarantine();
        self.terminal = true;
        self.terminal_failure = Some(String::from(
            "QEMU attempt aggregate resources were transferred to quarantine",
        ));
    }

    /// Checks cancellation and hard-resource state between bounded operations.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::AttemptOperational`] after terminal cleanup,
    /// cancellation, resource exhaustion, or enforcement-state failure.
    pub fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        if self.terminal {
            return Err(terminal_attempt_operational_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.check_operational_boundary().map_err(|error| {
            attempt_operational_error("check QEMU attempt operational boundary", error)
        })
    }
}

impl<G> QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    /// Provisions one fresh generation directory under the aggregate guard.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after aggregate cleanup or
    /// when the guard rejects launch admission or storage provisioning.
    pub fn prepare_generation_run_directory(
        &mut self,
        requirements: QemuLaunchResourceRequirements,
    ) -> Result<QemuPreparedRunDirectory, LifecycleApiError> {
        if self.terminal {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard
            .prepare_generation_run_directory(requirements)
            .map_err(|error| {
                generation_error(format!("prepare QEMU generation directory: {error}"))
            })
    }

    /// Returns the sealed attempt process contract for guarded generation spawn.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] after aggregate cleanup or
    /// when the guard cannot authenticate the retained process contract.
    pub fn child_process_contract(&self) -> Result<&QemuChildProcessContract, LifecycleApiError> {
        if self.terminal {
            return Err(generation_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.child_process_contract().map_err(|error| {
            generation_error(format!("lend QEMU generation process contract: {error}"))
        })
    }

    /// Retains an unreaped child from a failed generation launch.
    pub fn retain_failed_launch_child(&mut self, child: QemuNodeChild) {
        self.guard.retain_failed_launch_child(child);
    }

    /// Charges one scheduler quantum before generation guest progress.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::AttemptOperational`] on cancellation, terminal
    /// ownership, or exact quantum/resource exhaustion.
    pub fn charge_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        if self.terminal {
            return Err(terminal_attempt_operational_error(
                "QEMU attempt generation owner is already terminal",
            ));
        }
        self.guard.charge_execution_quantum().map_err(|error| {
            attempt_operational_error("charge QEMU generation execution quantum", error)
        })
    }
}

impl<G> Drop for QemuAttemptGenerationResourceOwner<G>
where
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        self.quarantine();
    }
}

#[derive(Debug)]
struct QemuAttemptGenerationState {
    maximum_nodes: usize,
    latest: BTreeMap<NodeId, u64>,
    active: BTreeSet<ProductionVmNodeGeneration>,
    abandoned: bool,
}

/// Linear release token for one exact production VM process generation.
#[must_use = "finish the generation lease only after exact QEMU reap"]
pub struct QemuAttemptGenerationLease {
    identity: ProductionVmNodeGeneration,
    generations: Arc<Mutex<QemuAttemptGenerationState>>,
    previous_generation: Option<u64>,
    finished: bool,
}

impl fmt::Debug for QemuAttemptGenerationLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QemuAttemptGenerationLease")
            .field("identity", &self.identity)
            .field("previous_generation", &self.previous_generation)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl QemuAttemptGenerationLease {
    /// Aborts a generation whose launch left no live or unreaped process.
    ///
    /// This is the only path that rolls back the latest-generation fence. It is
    /// reserved for the launcher that still owns proof that process spawn never
    /// happened or that every spawned child was synchronously reaped. A normal
    /// launched generation must instead remain monotone and use
    /// [`ProductionVmNodeLease::finish`] after reap.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when the registry is poisoned,
    /// this is no longer the exact active/latest generation, or the lease was
    /// already finished. Failure leaves the lease fail-closed so its `Drop`
    /// path poisons aggregate release.
    pub(crate) fn abort_without_process(mut self) -> Result<(), LifecycleApiError> {
        if self.finished {
            return Err(generation_error(
                "cannot abort an already-finished QEMU generation lease",
            ));
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        if state.latest.get(self.identity.node()).copied() != Some(self.identity.generation())
            || !state.active.remove(&self.identity)
        {
            state.abandoned = true;
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} is not the exact pending generation",
                self.identity.node().name,
                self.identity.generation()
            )));
        }
        match self.previous_generation {
            Some(previous) => {
                state.latest.insert(self.identity.node().clone(), previous);
            }
            None => {
                state.latest.remove(self.identity.node());
            }
        }
        self.finished = true;
        Ok(())
    }
}

impl ProductionVmNodeLease for QemuAttemptGenerationLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        if self.finished {
            return Ok(());
        }
        let mut state = self
            .generations
            .lock()
            .map_err(|_| generation_error("QEMU attempt generation registry is poisoned"))?;
        if !state.active.remove(&self.identity) {
            state.abandoned = true;
            return Err(generation_error(format!(
                "QEMU node `{}` generation {} has no active lease",
                self.identity.node().name,
                self.identity.generation()
            )));
        }
        self.finished = true;
        Ok(())
    }
}

impl Drop for QemuAttemptGenerationLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        match self.generations.lock() {
            Ok(mut state) => state.abandoned = true,
            Err(poisoned) => poisoned.into_inner().abandoned = true,
        }
    }
}
