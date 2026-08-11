//! Construction and tuning of production VM lifecycle configurations.

use super::*;

impl ProductionVmLifecycleConfig {
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
            root_image_format: ProductionRootImageFormat::Qcow2,
            run_state_root: run_state_root.into(),
            run_ceiling_icount: DEFAULT_RUN_CEILING_ICOUNT,
            quantum_budget: DEFAULT_QUANTUM_BUDGET,
            rendezvous_interval_icount: None,
            completion_timeout: Duration::from_secs(240),
            coverage: ProductionPluginSwitch::Off,
            debug_gateway_executable: None,
            debug: None,
            branch: None,
            branch_network_choices: Vec::new(),
            signal_artifacts: None,
            world_artifacts: None,
            validate_guest_asset_references: false,
        }
    }

    /// Returns this configuration with the materialized initrd passed to QEMU.
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

    /// Returns this configuration with fail-closed boot-asset reference validation.
    ///
    /// When enabled, every declared kernel and root-image content reference must
    /// equal the BLAKE3 digest of the concrete file selected for that architecture.
    #[must_use]
    pub const fn with_guest_asset_reference_validation(mut self) -> Self {
        self.validate_guest_asset_references = true;
        self
    }

    /// Returns this configuration with the immutable root image's format.
    #[must_use]
    pub const fn with_root_image_format(mut self, format: ProductionRootImageFormat) -> Self {
        self.root_image_format = format;
        self
    }

    /// Returns this configuration with a different terminal icount ceiling.
    #[must_use]
    pub const fn with_run_ceiling_icount(mut self, ceiling: u64) -> Self {
        self.run_ceiling_icount = ceiling;
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
    /// The interval is expressed in guest instructions and deterministically
    /// caps each scheduler RUN without changing the terminal run ceiling.
    #[must_use]
    pub const fn with_rendezvous_interval_icount(mut self, interval: u64) -> Self {
        self.rendezvous_interval_icount = Some(interval);
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
    pub const fn with_coverage(mut self, coverage: ProductionPluginSwitch) -> Self {
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

    /// Returns this configuration with one mediated QEMU gdbstub channel.
    ///
    /// `node` selects a World VM by canonical name. When omitted, the first VM
    /// owns the debugger channel. The operator listener accepts the same stable
    /// address syntax as [`GdbListen`], including `127.0.0.1:0`.
    #[must_use]
    pub fn with_debug_gdbstub(
        mut self,
        node: Option<String>,
        operator_listen: impl Into<String>,
    ) -> Self {
        self.debug = Some(ProductionVmDebugConfig {
            node,
            operator_listen: operator_listen.into(),
            all_nodes: false,
            allow_requested_loopback_listen: false,
        });
        self
    }

    /// Returns this configuration with mediated gdbstub backends for every node.
    ///
    /// The operator listener is still created lazily for one requested node at
    /// a time. A caller may select any loopback listener; the configured value
    /// remains the default used by clients that do not request one explicitly.
    /// This mode is intended for a long-lived daemon whose submitted scenarios
    /// are not known when the server configuration is constructed.
    #[must_use]
    pub fn with_debug_gdbstubs_for_all_nodes(mut self, operator_listen: impl Into<String>) -> Self {
        self.debug = Some(ProductionVmDebugConfig {
            node: None,
            operator_listen: operator_listen.into(),
            all_nodes: true,
            allow_requested_loopback_listen: true,
        });
        self
    }

    /// Returns this configuration with explorer overrides admitted at `frontier`.
    ///
    /// The lifecycle waits until deterministic replay reaches both the exact
    /// base configuration and saved frontier, then records the supplied
    /// overrides before any further backend advance.
    #[must_use]
    pub fn with_branch_prefix_overrides(
        mut self,
        base: Configuration,
        frontier: VirtualTime,
        decisions: Vec<Decision>,
    ) -> Self {
        self.branch = Some(ProductionVmBranchConfig {
            base,
            frontier,
            decisions,
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
            decisions: Vec::new(),
            seed: Some(seed),
        });
        self
    }

    /// Returns this configuration with exact live World-network branch choices.
    #[must_use]
    pub fn with_branch_network_choices(mut self, choices: Vec<crucible::OverrideDecision>) -> Self {
        self.branch_network_choices = choices;
        self
    }

    /// Returns this configuration with the content-addressed signal artifact provider.
    #[must_use]
    pub fn with_signal_artifacts(mut self, artifacts: Arc<dyn SignalArtifactProvider>) -> Self {
        self.signal_artifacts = Some(artifacts);
        self
    }

    /// Returns this configuration with the content-addressed World artifact store.
    #[must_use]
    pub fn with_world_artifacts(mut self, artifacts: Arc<dyn DagStore>) -> Self {
        self.world_artifacts = Some(artifacts);
        self
    }

    pub(super) fn for_thin_replay(self) -> Self {
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
