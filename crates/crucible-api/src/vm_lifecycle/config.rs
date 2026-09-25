//! Construction and tuning of production VM lifecycle configurations.

use super::*;

impl ProductionVmLifecycleConfig {
    /// Returns the selected QEMU executable.
    #[must_use]
    pub fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    /// Returns the selected QEMU plugin.
    #[must_use]
    pub fn plugin(&self) -> &std::path::Path {
        &self.plugin
    }

    /// Returns the durable lifecycle recovery root.
    #[must_use]
    pub fn run_state_root(&self) -> &std::path::Path {
        &self.run_state_root
    }

    /// Returns the wall-clock ceiling for one QEMU lifecycle operation.
    #[must_use]
    pub const fn completion_timeout(&self) -> Duration {
        self.completion_timeout
    }

    /// Returns the terminal shared-timeline tick ceiling for this lifecycle.
    #[must_use]
    pub const fn run_ceiling_ticks(&self) -> u64 {
        self.run_ceiling_ticks
    }

    /// Returns the production lifecycle quantum budget.
    #[must_use]
    pub const fn quantum_budget(&self) -> u64 {
        self.quantum_budget
    }

    /// Returns the operational host-worker ceiling for concurrent QEMU advances.
    #[must_use]
    pub const fn maximum_host_workers(&self) -> usize {
        self.maximum_host_workers
    }

    /// Returns this configuration with the selected bounded host-worker ceiling.
    ///
    /// Lifecycle construction rejects zero or values above the production
    /// maximum before allocating host resources. The ceiling governs host
    /// dispatch only; it does not enter canonical scheduler state.
    #[must_use]
    pub const fn with_maximum_host_workers(mut self, maximum: usize) -> Self {
        self.maximum_host_workers = maximum;
        self
    }

    /// Returns the configured fixed scheduler rendezvous interval.
    #[must_use]
    pub const fn rendezvous_interval_ticks(&self) -> Option<u64> {
        self.rendezvous_interval_ticks
    }

    /// Returns the observation-only coverage switch.
    #[must_use]
    pub const fn coverage(&self) -> QemuLaunchPluginSwitch {
        self.coverage
    }

    /// Returns the authoritative signal artifact store, when configured.
    #[must_use]
    pub fn signal_artifacts(&self) -> Option<&dyn DagStore> {
        self.signal_artifacts.as_deref()
    }

    /// Returns the authoritative World artifact store, when configured.
    #[must_use]
    pub fn world_artifacts(&self) -> Option<&dyn DagStore> {
        self.world_artifacts.as_deref()
    }

    /// Returns this configuration with a distinct durable recovery root.
    ///
    /// Fixed worker pools use stable per-worker children so concurrent runs of
    /// one scenario do not share the scenario-wide recovery lock. The caller
    /// must preserve each worker-to-root assignment across daemon restart.
    #[must_use]
    pub fn with_run_state_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.run_state_root = root.into();
        self
    }

    /// Builds a local-QEMU lifecycle configuration with bounded defaults.
    ///
    /// `run_state_root` must be a durable writable directory. Each scenario
    /// receives an isolated process manifest and lifecycle journal beneath it;
    /// there is no ephemeral recovery fallback.
    #[must_use]
    pub fn new(
        executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
        run_state_root: impl Into<PathBuf>,
    ) -> Self {
        Self::new_for_guest_architecture(
            executable,
            plugin,
            VmArchitecture::X86_64,
            kernel,
            root_image,
            run_state_root,
        )
    }

    /// Builds a local-QEMU lifecycle configuration for one native guest architecture.
    ///
    /// `run_state_root` has the same durable recovery contract as [`Self::new`].
    #[must_use]
    pub fn new_for_guest_architecture(
        executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        architecture: VmArchitecture,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
        run_state_root: impl Into<PathBuf>,
    ) -> Self {
        let mut guest_assets = BTreeMap::new();
        guest_assets.insert(
            architecture,
            ProductionVmGuestAssets {
                kernel: kernel.into(),
                root_image: root_image.into(),
                kernel_cmdline_prefix: None,
            },
        );
        Self {
            executable: executable.into(),
            plugin: plugin.into(),
            native_guest_architecture: architecture,
            guest_assets,
            initrd: None,
            kernel_cmdline_prefix: None,
            root_image_format: QemuRootImageFormat::Qcow2,
            run_state_root: run_state_root.into(),
            run_ceiling_ticks: DEFAULT_RUN_CEILING_TICKS,
            quantum_budget: DEFAULT_QUANTUM_BUDGET,
            maximum_host_workers: quantum_loop::MAX_PRODUCTION_QEMU_HOST_WORKERS,
            rendezvous_interval_ticks: None,
            completion_timeout: Duration::from_secs(240),
            coverage: QemuLaunchPluginSwitch::Off,
            debug_gateway_executable: None,
            debug: None,
            branch: None,
            continuation_branches: Vec::new(),
            signal_fault_replay: None,
            branch_network_choices: Vec::new(),
            app_random_branch_selections: BTreeMap::new(),
            app_random_branch_plans: BTreeMap::new(),
            signal_artifacts: None,
            fault_replay: None,
            world_artifacts: None,
            bounded_scheduler_preemption: None,
        }
    }

    /// Returns this configuration with one pidfd-authenticated host preemption sequence.
    ///
    /// The production lifecycle applies the bounded sequence to the first VM's
    /// first scheduler quantum and writes its non-canonical report to
    /// `evidence`. This hook is intended for native replay gates that compare
    /// canonical guest identity across different host scheduling profiles.
    #[must_use]
    pub fn with_bounded_scheduler_preemption(
        self,
        evidence: crucible_qemu::BoundedSchedulerPreemptionEvidence,
    ) -> Self {
        self.with_bounded_scheduler_preemption_flights(vec![evidence])
    }

    #[must_use]
    fn with_bounded_scheduler_preemption_flights(
        mut self,
        evidence: Vec<crucible_qemu::BoundedSchedulerPreemptionEvidence>,
    ) -> Self {
        self.bounded_scheduler_preemption = Some(BoundedSchedulerPreemptionFlights::new(evidence));
        self
    }

    pub(super) fn claim_bounded_scheduler_preemption(
        &self,
    ) -> Result<
        Option<crucible_qemu::BoundedSchedulerPreemptionEvidenceClaim>,
        BoundedSchedulerPreemptionFlightError,
    > {
        self.bounded_scheduler_preemption
            .as_ref()
            .map(BoundedSchedulerPreemptionFlights::claim_next)
            .transpose()
    }

    /// Returns this configuration with the initrd selected by nodes that declare its hash.
    #[must_use]
    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    /// Returns this configuration with package-owned kernel command-line pins.
    #[must_use]
    pub fn with_kernel_cmdline_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.kernel_cmdline_prefix = Some(prefix.into());
        self
    }

    /// Returns this configuration with boot artifacts for another guest architecture.
    #[must_use]
    pub fn with_guest_assets(
        mut self,
        architecture: VmArchitecture,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
        kernel_cmdline_prefix: Option<String>,
    ) -> Self {
        self.guest_assets.insert(
            architecture,
            ProductionVmGuestAssets {
                kernel: kernel.into(),
                root_image: root_image.into(),
                kernel_cmdline_prefix,
            },
        );
        self
    }

    /// Returns this configuration with the immutable root image's format.
    #[must_use]
    pub const fn with_root_image_format(mut self, format: QemuRootImageFormat) -> Self {
        self.root_image_format = format;
        self
    }

    /// Returns this configuration with a different terminal timeline ceiling.
    #[must_use]
    pub const fn with_run_ceiling_ticks(mut self, ceiling: u64) -> Self {
        self.run_ceiling_ticks = ceiling;
        self
    }

    /// Returns this configuration with a different scheduler quantum budget.
    #[must_use]
    pub const fn with_quantum_budget(mut self, budget: u64) -> Self {
        self.quantum_budget = budget;
        self
    }

    /// Returns this configuration with a fixed scheduler rendezvous interval.
    ///
    /// The interval is expressed in exact simulation ticks and deterministically
    /// caps each scheduler RUN without changing the terminal run ceiling.
    #[must_use]
    pub const fn with_rendezvous_interval_ticks(mut self, interval: u64) -> Self {
        self.rendezvous_interval_ticks = Some(interval);
        self
    }

    /// Returns this configuration with a different per-node completion timeout.
    #[must_use]
    pub const fn with_completion_timeout(mut self, timeout: Duration) -> Self {
        self.completion_timeout = timeout;
        self
    }

    /// Returns this configuration with observation-only basic-block coverage.
    #[must_use]
    pub const fn with_coverage(mut self, coverage: QemuLaunchPluginSwitch) -> Self {
        self.coverage = coverage;
        self
    }

    /// Returns this configuration with the standalone debugger gateway executable.
    ///
    /// The executable remains a separate GPL-side process. The production
    /// lifecycle communicates with it only through the versioned Unix control
    /// protocol owned by `crucible-protocol`.
    #[must_use]
    pub fn with_debug_gateway(mut self, executable: impl Into<PathBuf>) -> Self {
        self.debug_gateway_executable = Some(executable.into());
        self
    }

    #[must_use]
    fn with_debug_gdbstubs_for_all_nodes(mut self, operator_listen: impl Into<String>) -> Self {
        self.debug = Some(ProductionVmDebugConfig {
            node: None,
            operator_listen: operator_listen.into(),
            all_nodes: true,
            allow_requested_loopback_listen: true,
        });
        self
    }

    /// Returns this configuration with all-node debugging when policy authorizes it.
    ///
    /// Production debugger replay records an exact execution fingerprint at
    /// every scheduler boundary. The daemon therefore configures gdbstubs and
    /// their evidence capture only when its immutable startup authorization
    /// policy admits at least one debugger principal.
    #[must_use]
    pub fn with_authorized_debug_gdbstubs_for_all_nodes(
        mut self,
        operator_listen: impl Into<String>,
        authorization: &crate::DebugAuthorizationPolicy,
    ) -> Self {
        if authorization.admits_debugging() {
            self.with_debug_gdbstubs_for_all_nodes(operator_listen)
        } else {
            self.debug = None;
            self
        }
    }

    /// Returns whether this lifecycle will expose mediated QEMU gdbstubs.
    #[must_use]
    pub const fn debug_gdbstubs_enabled(&self) -> bool {
        self.debug.is_some()
    }

    /// Returns this configuration with an exact branch boundary at `frontier`.
    #[must_use]
    pub fn with_branch_boundary(mut self, base: Configuration, frontier: VirtualTime) -> Self {
        self.branch = Some(ProductionVmBranchConfig {
            base,
            frontier,
            seed: None,
        });
        self
    }

    /// Returns this configuration with decision streams re-seeded at `frontier`.
    ///
    /// Prefix replay continues under the scenario seed. Once the authoritative
    /// scheduler reaches both `base` and the saved frontier, every future
    /// scheduler, network, block/9p, and live app-random decision stream
    /// restarts from cursor zero under `seed`.
    #[must_use]
    pub fn with_branch_reseed(
        mut self,
        base: Configuration,
        frontier: VirtualTime,
        seed: Seed,
    ) -> Self {
        self.branch = Some(ProductionVmBranchConfig {
            base,
            frontier,
            seed: Some(seed),
        });
        self
    }

    /// Appends a decision-stream re-seed to an ordered cold-replay branch plan.
    ///
    /// Each branch is applied at its exact configuration and frontier. The
    /// sequence allows a cold replay to reconstruct multiple controlled
    /// continuation generations without collapsing an earlier seed transition.
    #[must_use]
    pub fn append_branch_reseed(
        mut self,
        base: Configuration,
        frontier: VirtualTime,
        seed: Seed,
    ) -> Self {
        self.continuation_branches.push(ProductionVmBranchConfig {
            base,
            frontier,
            seed: Some(seed),
        });
        self
    }

    /// Appends an exact boundary to an ordered cold-replay branch plan.
    #[must_use]
    pub fn append_branch_boundary(mut self, base: Configuration, frontier: VirtualTime) -> Self {
        self.continuation_branches.push(ProductionVmBranchConfig {
            base,
            frontier,
            seed: None,
        });
        self
    }

    /// Returns this configuration with exact promoted signal-fault replay.
    ///
    /// The plan must already have been reconstructed from repository-
    /// authenticated campaign records. Production construction checks that its
    /// target is the admitted start configuration, installs every finite
    /// producer override before launch, and injects each typed branch at its
    /// exact parent and virtual-time boundary.
    #[must_use]
    pub fn with_signal_fault_campaign_replay(
        mut self,
        replay: SignalFaultCampaignReplayPlan,
    ) -> Self {
        self.signal_fault_replay = Some(replay);
        self
    }

    /// Returns this configuration with exact live World-network branch choices.
    #[must_use]
    pub fn with_branch_network_choices(
        mut self,
        choices: Vec<crucible::SelectionDecision>,
    ) -> Self {
        self.branch_network_choices = choices;
        self
    }

    /// Returns this configuration with additional exact World-network choices.
    #[must_use]
    pub fn append_branch_network_choices(
        mut self,
        choices: impl IntoIterator<Item = crucible::SelectionDecision>,
    ) -> Self {
        self.branch_network_choices.extend(choices);
        self
    }

    /// Returns this configuration with exact app-random branch replay inputs.
    ///
    /// `selections` binds authenticated schedule selections to their exact
    /// post-draw parents. `plans` contains the corresponding node-local producer
    /// substitutions sent to each plugin during setup.
    #[must_use]
    pub fn with_app_random_branch_replay(
        mut self,
        selections: BTreeMap<ContentHash, crucible::SelectionDecision>,
        plans: BTreeMap<NodeId, crucible_protocol::app_random_branch_plan::AppRandomBranchPlan>,
    ) -> Self {
        self.app_random_branch_selections = selections;
        self.app_random_branch_plans = plans;
        self
    }

    /// Returns this configuration with an authoritative resolved-effect replay.
    ///
    /// The lifecycle validates and installs the trace before the first QEMU
    /// quantum and rejects a successful shutdown unless every work item was
    /// consumed.
    #[must_use]
    pub fn with_fault_replay(mut self, trace: ResolvedEffectTrace) -> Self {
        self.fault_replay = Some(trace);
        self
    }

    /// Returns this configuration with the authoritative signal artifact store.
    ///
    /// Exact checkpoints copy every transitively referenced signal object into
    /// their authenticated execution closure, so direct restore does not depend
    /// on this original store remaining available.
    #[must_use]
    pub fn with_signal_artifacts(mut self, artifacts: Arc<dyn DagStore>) -> Self {
        self.signal_artifacts = Some(artifacts);
        self
    }

    /// Returns this configuration with the content-addressed World artifact store.
    #[must_use]
    pub fn with_world_artifacts(mut self, artifacts: Arc<dyn DagStore>) -> Self {
        self.world_artifacts = Some(artifacts);
        self
    }

    /// Returns a conservative bound for driving through the configured budget.
    ///
    /// The scheduler budget is already a count of authoritative quanta. The
    /// additional per-node pass covers scheduler-only boundaries and terminal
    /// settling after the final admitted quantum.
    #[must_use]
    pub fn maximum_scheduler_quanta(&self, node_count: usize) -> u64 {
        let node_count = u64::try_from(node_count).unwrap_or(u64::MAX).max(1);
        self.quantum_budget
            .saturating_add(node_count)
            .saturating_add(1)
    }
}

impl ProductionVmLifecycleLoop {
    /// Retains an external resource owner until this lifecycle is dropped.
    ///
    /// Prepared resume paths use this to keep request-local checkpoint and run
    /// state directories alive through every restored process generation. The
    /// owner is declared after process and run-directory fields so it is
    /// released only after those resources have begun teardown.
    #[must_use]
    pub fn with_retained_resource_owner(mut self, owner: impl Send + 'static) -> Self {
        self.retained_resource_owners.push(Box::new(owner));
        self
    }
}

#[cfg(test)]
mod tests {
    use crucible_session::DebugRole;

    use super::*;

    #[test]
    fn recovery_root_replacement_is_clone_local() {
        let base =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "shared-state");
        let worker = base.clone().with_run_state_root("worker-state/worker-001");

        assert_eq!(base.run_state_root(), Path::new("shared-state"));
        assert_eq!(
            worker.run_state_root(),
            Path::new("worker-state/worker-001")
        );
    }

    #[test]
    fn bounded_scheduler_preemption_is_opt_in_and_single_flight() {
        let base =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state");
        assert!(base.bounded_scheduler_preemption.is_none());

        let evidence = crucible_qemu::BoundedSchedulerPreemptionEvidence::default();
        let enabled = base.with_bounded_scheduler_preemption(evidence.clone());
        assert!(enabled.bounded_scheduler_preemption.is_some());
        let claim = enabled
            .claim_bounded_scheduler_preemption()
            .unwrap_or_else(|error| panic!("first flight should claim evidence: {error}"))
            .unwrap_or_else(|| panic!("enabled flight should return a claim"));
        assert!(evidence.snapshot().is_none());
        drop(claim);
        assert!(enabled.claim_bounded_scheduler_preemption().is_err());
        assert!(evidence.snapshot().is_none());
    }

    #[test]
    fn bounded_scheduler_preemption_clones_consume_distinct_flights() {
        let first = crucible_qemu::BoundedSchedulerPreemptionEvidence::default();
        let second = crucible_qemu::BoundedSchedulerPreemptionEvidence::default();
        let config =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state")
                .with_bounded_scheduler_preemption_flights(vec![first.clone(), second.clone()]);
        let clone = config.clone();

        let first_claim = config
            .claim_bounded_scheduler_preemption()
            .unwrap_or_else(|error| panic!("first flight should claim evidence: {error}"))
            .unwrap_or_else(|| panic!("configured first flight should return a claim"));
        let second_claim = clone
            .claim_bounded_scheduler_preemption()
            .unwrap_or_else(|error| panic!("second flight should claim evidence: {error}"))
            .unwrap_or_else(|| panic!("configured second flight should return a claim"));

        assert!(config.claim_bounded_scheduler_preemption().is_err());
        drop(first_claim);
        drop(second_claim);
        assert!(first.claim().is_err());
        assert!(second.claim().is_err());
    }

    #[test]
    fn daemon_debug_evidence_follows_startup_authorization() {
        let base =
            ProductionVmLifecycleConfig::new("qemu", "plugin", "kernel", "root", "run-state");
        let denied = base
            .clone()
            .with_debug_gdbstubs_for_all_nodes("127.0.0.1:1")
            .with_authorized_debug_gdbstubs_for_all_nodes(
                "127.0.0.1:0",
                &crate::DebugAuthorizationPolicy::deny_all(),
            );
        assert!(denied.debug.is_none());

        let mut authorized = crate::DebugAuthorizationPolicy::deny_all();
        authorized.grant_trusted_unauthenticated_role(DebugRole::observer());
        let enabled = base.with_authorized_debug_gdbstubs_for_all_nodes("127.0.0.1:0", &authorized);
        let debug = enabled
            .debug
            .as_ref()
            .unwrap_or_else(|| panic!("authorized daemon debugging should be configured"));
        assert!(debug.all_nodes);
        assert!(debug.allow_requested_loopback_listen);
        assert_eq!(debug.operator_listen, "127.0.0.1:0");
    }
}
