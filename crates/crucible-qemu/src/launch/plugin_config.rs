//! Production plugin launch configuration and inherited descriptors.

use super::*;

const PLUGIN_ARG_SIMFD: &str = "simfd";
const PLUGIN_ARG_SLOT: &str = "slot";
const PLUGIN_ARG_FAULT_NODE_HASH: &str = "fault_node_hash";
const PLUGIN_ARG_PROCESS_GENERATION: &str = "process_generation";
const PLUGIN_ARG_NETWORK_TX_NEXT_SEQ: &str = "network_tx_next_seq";
const PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS: &str = "storage_completed_history_epochs";
const PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_GAPS: &str = "storage_completed_history_gaps";
const PLUGIN_ARG_SHMEMFD: &str = "shmemfd";
const PLUGIN_ARG_WAKEFD: &str = "wakefd";
const PLUGIN_ARG_WHITEBOX: &str = "whitebox";
const PLUGIN_ARG_WHITEBOX_SETUP: &str = "whitebox_setup";
const PLUGIN_ARG_APP_RANDOM_SEED: &str = "app_random_seed";
const PLUGIN_ARG_APP_RANDOM_CAP: &str = "app_random_cap";
const PLUGIN_ARG_APP_RANDOM_NODE: &str = "app_random_node";
const PLUGIN_ARG_APP_RANDOM_BRANCH_SEED: &str = "app_random_branch_seed";
const PLUGIN_ARG_APP_RANDOM_BRANCH_AFTER: &str = "app_random_branch_after";
const PLUGIN_ARG_APP_RANDOM_DRAW_OFFSET: &str = "app_random_draw_offset";
const PLUGIN_ARG_APP_RANDOM_POSITIONS: &str = "app_random_positions";
const PLUGIN_ARG_COVERAGE: &str = "coverage";
const PLUGIN_ARG_FINGERPRINT: &str = "fingerprint";
const PLUGIN_ARG_FINGERPRINT_ORACLE: &str = "fingerprint_oracle";
const PLUGIN_ARG_STATE_DUMP_TARGET: &str = "state_dump_target";
const PLUGIN_ARG_STATE_DUMP_PATH: &str = "state_dump_path";

/// Plugin descriptors inherited at fixed child fd numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLaunchInheritedFds {
    /// Pre-inherited shared-memory descriptor.
    pub shmem_fd: i32,
    /// Pre-inherited wake descriptor.
    pub wake_fd: i32,
}

impl QemuLaunchInheritedFds {
    /// Builds the inherited descriptor pair.
    #[must_use]
    pub const fn new(shmem_fd: i32, wake_fd: i32) -> Self {
        Self { shmem_fd, wake_fd }
    }
}

/// A boolean feature switch in the QEMU plugin launch argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuLaunchPluginSwitch {
    /// The feature is disabled.
    Off,
    /// The feature is enabled.
    On,
}

/// Seed and bound passed to the production plugin's app-random doorbell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchAppRandomConfig {
    /// Low 64-bit compatibility projection of the complete scenario seed.
    pub scenario_seed: u64,
    authoritative_seed: Seed,
    /// Derived L0 decision-RNG root consumed by the synchronous plugin adapter.
    pub decision_rng_root_seed: u64,
    /// Scenario-hashed maximum number of app-random draws.
    pub draw_cap: u64,
    /// Canonical scheduler node name used in the name-hashed stream identity.
    pub node_name: String,
    /// Optional derived decision-RNG root for a forked future.
    pub branch_decision_rng_root_seed: Option<u64>,
    branch_seed: Option<Seed>,
    /// Number of this node's prefix draws served before the branch seed applies.
    pub branch_after_draws: Option<u64>,
    /// Node-local draws already consumed before this process launches.
    pub draw_offset: u64,
    /// Per-stream positions already consumed before this process launches.
    pub stream_positions: BTreeMap<String, u64>,
    /// Immutable node-local campaign selections supplied during setup.
    branch_plan: crucible_protocol::app_random_branch_plan::AppRandomBranchPlan,
}

impl QemuLaunchAppRandomConfig {
    /// Builds a complete live app-random launch configuration.
    #[must_use]
    pub fn new(root_seed: u64, draw_cap: u64, node_name: impl Into<String>) -> Self {
        Self::from_seed(Seed::from_u64(root_seed), draw_cap, node_name)
    }

    /// Builds a live app-random launch configuration from the complete scenario seed.
    #[must_use]
    pub fn from_seed(seed: Seed, draw_cap: u64, node_name: impl Into<String>) -> Self {
        let seed_bytes = seed.bytes();
        let mut scenario_seed = [0_u8; 8];
        scenario_seed.copy_from_slice(&seed_bytes[..8]);
        Self {
            scenario_seed: u64::from_le_bytes(scenario_seed),
            authoritative_seed: seed,
            decision_rng_root_seed: seed.decision_rng_root_seed(),
            draw_cap,
            node_name: node_name.into(),
            branch_decision_rng_root_seed: None,
            branch_seed: None,
            branch_after_draws: None,
            draw_offset: 0,
            stream_positions: BTreeMap::new(),
            branch_plan: crucible_protocol::app_random_branch_plan::AppRandomBranchPlan::default(),
        }
    }

    /// Returns this configuration with an exact app-random branch boundary.
    ///
    /// The plugin serves `prefix_draws` requests from the scenario seed, then
    /// clears every node-local stream and serves all later requests from
    /// `branch_seed` at cursor zero.
    #[must_use]
    pub fn with_branch_reseed(mut self, branch_seed: u64, prefix_draws: u64) -> Self {
        self = self.with_branch_seed(Seed::from_u64(branch_seed), prefix_draws);
        self
    }

    /// Returns this configuration with a complete branch seed at an exact boundary.
    #[must_use]
    pub fn with_branch_seed(mut self, branch_seed: Seed, prefix_draws: u64) -> Self {
        self.branch_decision_rng_root_seed = Some(branch_seed.decision_rng_root_seed());
        self.branch_seed = Some(branch_seed);
        self.branch_after_draws = Some(prefix_draws);
        self
    }

    /// Returns the complete scenario seed retained for host-side validation.
    #[must_use]
    pub(crate) const fn authoritative_seed(&self) -> Seed {
        self.authoritative_seed
    }

    /// Returns the complete optional branch seed retained for host-side validation.
    #[must_use]
    pub(crate) const fn branch_seed(&self) -> Option<Seed> {
        self.branch_seed
    }

    /// Returns this configuration with authoritative continuation cursors.
    ///
    /// This is used when a crashed VM process is relaunched: the replacement
    /// plugin resumes the active decision seed without replaying already-served
    /// application draws.
    #[must_use]
    pub fn with_continuation(
        mut self,
        draw_offset: u64,
        stream_positions: BTreeMap<String, u64>,
    ) -> Self {
        self.draw_offset = draw_offset;
        self.stream_positions = stream_positions;
        self
    }

    /// Returns this configuration with an immutable campaign branch plan.
    #[must_use]
    pub fn with_branch_plan(
        mut self,
        branch_plan: crucible_protocol::app_random_branch_plan::AppRandomBranchPlan,
    ) -> Self {
        self.branch_plan = branch_plan;
        self
    }

    /// Returns the immutable campaign branch plan for this node generation.
    #[must_use]
    pub const fn branch_plan(
        &self,
    ) -> &crucible_protocol::app_random_branch_plan::AppRandomBranchPlan {
        &self.branch_plan
    }
}

impl fmt::Display for QemuLaunchPluginSwitch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Off => f.write_str("off"),
            Self::On => f.write_str("on"),
        }
    }
}

/// A description of the `-plugin` command-line argument.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchPluginConfig {
    plugin_path: String,
    slot: u32,
    fault_node_hash: [u8; 32],
    process_generation: u64,
    network_tx_next_seq: u32,
    storage_completed_history_epochs: u64,
    storage_completed_history_gaps: u64,
    whitebox: QemuLaunchPluginSwitch,
    whitebox_setup: Option<QemuWhiteboxSetupValidation>,
    app_random: Option<QemuLaunchAppRandomConfig>,
    selectable_catalog_plan:
        Option<crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
    coverage: QemuLaunchPluginSwitch,
    fingerprint: QemuLaunchPluginSwitch,
    fingerprint_oracle: QemuLaunchPluginSwitch,
    state_dump: Option<(u64, String)>,
}

impl QemuLaunchPluginConfig {
    /// Builds the required plugin launch config.
    #[must_use]
    pub fn new(plugin_path: impl Into<String>, slot: u32) -> Self {
        let standalone_identity = format!("standalone-vm-slot-{slot}");
        let resource_limits = crucible::model::FaultResourceLimits::default();
        Self {
            plugin_path: plugin_path.into(),
            slot,
            fault_node_hash: qemu_fault_target_hash(&standalone_identity),
            process_generation: 1,
            network_tx_next_seq: 0,
            storage_completed_history_epochs: resource_limits.storage_completed_history_epochs,
            storage_completed_history_gaps: resource_limits.storage_completed_history_gaps,
            whitebox: QemuLaunchPluginSwitch::Off,
            whitebox_setup: None,
            app_random: None,
            selectable_catalog_plan: None,
            coverage: QemuLaunchPluginSwitch::Off,
            fingerprint: QemuLaunchPluginSwitch::Off,
            fingerprint_oracle: QemuLaunchPluginSwitch::Off,
            state_dump: None,
        }
    }

    /// Returns a config bound to the canonical scenario node identity.
    #[must_use]
    pub fn with_fault_target_node(mut self, node_name: &str) -> Self {
        self.fault_node_hash = qemu_fault_target_hash(node_name);
        self
    }

    /// Returns the exact hash authenticated by the plugin fault bridge.
    #[must_use]
    pub const fn fault_node_hash(&self) -> [u8; 32] {
        self.fault_node_hash
    }

    /// Returns a config bound to one nonzero host-supervised process generation.
    #[must_use]
    pub const fn with_process_generation(mut self, process_generation: u64) -> Self {
        self.process_generation = process_generation;
        self
    }

    /// Returns the generation provisioned before this process accepts faults.
    #[must_use]
    pub const fn process_generation(&self) -> u64 {
        self.process_generation
    }

    /// Returns a config continuing the plugin-owned network TX sequence.
    #[must_use]
    pub const fn with_network_tx_next_sequence(mut self, next_sequence: u32) -> Self {
        self.network_tx_next_seq = next_sequence;
        self
    }

    /// Returns the next plugin-owned network TX sequence.
    #[must_use]
    pub const fn network_tx_next_sequence(&self) -> u32 {
        self.network_tx_next_seq
    }

    /// Returns a config carrying the authored completed block-history limits.
    #[must_use]
    pub const fn with_storage_completed_history_limits(mut self, epochs: u64, gaps: u64) -> Self {
        self.storage_completed_history_epochs = epochs;
        self.storage_completed_history_gaps = gaps;
        self
    }

    /// Returns the authored completed block-history epoch limit.
    #[must_use]
    pub const fn storage_completed_history_epochs(&self) -> u64 {
        self.storage_completed_history_epochs
    }

    /// Returns the authored completed block-history gap limit.
    #[must_use]
    pub const fn storage_completed_history_gaps(&self) -> u64 {
        self.storage_completed_history_gaps
    }

    /// Returns a config with the white-box hook switch set.
    #[must_use]
    pub fn with_whitebox(mut self, whitebox: QemuLaunchPluginSwitch) -> Self {
        self.whitebox = whitebox;
        self
    }

    /// Returns a config carrying a live setup-time doorbell collision proof.
    #[must_use]
    pub fn with_whitebox_setup(mut self, validation: QemuWhiteboxSetupValidation) -> Self {
        self.whitebox_setup = Some(validation);
        self
    }

    /// Returns a config carrying the seeded live app-random decision source.
    #[must_use]
    pub fn with_app_random(mut self, config: QemuLaunchAppRandomConfig) -> Self {
        self.app_random = Some(config);
        self
    }

    /// Returns a config carrying the launch-authenticated guest-selectable catalog.
    #[must_use]
    pub fn with_selectable_catalog_plan(
        mut self,
        plan: crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan,
    ) -> Self {
        self.selectable_catalog_plan = Some(plan);
        self
    }

    /// Returns a config with the coverage hook switch set.
    #[must_use]
    pub fn with_coverage(mut self, coverage: QemuLaunchPluginSwitch) -> Self {
        self.coverage = coverage;
        self
    }

    /// Returns a config with the single-VM fingerprint sampling switch set.
    ///
    /// The `fingerprint` argument is emitted only when it is `On`, so a config
    /// that leaves sampling off produces a byte-identical plugin argument string
    /// to the pre-fingerprint ABI and does not perturb existing argv attestation.
    #[must_use]
    pub fn with_fingerprint(mut self, fingerprint: QemuLaunchPluginSwitch) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    /// Returns a config with gate-only synchronous fingerprint comparison set.
    ///
    /// This switch deliberately retains the old vCPU-thread digest only as an
    /// acceptance oracle. Production launches leave it off.
    #[must_use]
    pub fn with_fingerprint_oracle(mut self, oracle: QemuLaunchPluginSwitch) -> Self {
        self.fingerprint_oracle = oracle;
        self
    }

    /// Returns a config that terminally exports full raw state at `target_icount`.
    #[must_use]
    pub fn with_terminal_state_dump(
        mut self,
        target_icount: u64,
        output_path: impl Into<String>,
    ) -> Self {
        self.state_dump = Some((target_icount, output_path.into()));
        self
    }

    /// Returns the plugin shared-object path.
    #[must_use]
    pub fn plugin_path(&self) -> &str {
        &self.plugin_path
    }

    /// Returns the host-to-plugin control socket descriptor.
    #[must_use]
    pub const fn sim_fd(&self) -> i32 {
        FIXED_PLUGIN_SIM_FD
    }

    /// Returns the node slot passed to the plugin.
    #[must_use]
    pub const fn slot(&self) -> u32 {
        self.slot
    }

    /// Returns the white-box hook switch passed to the plugin.
    #[must_use]
    pub const fn whitebox(&self) -> QemuLaunchPluginSwitch {
        self.whitebox
    }

    /// Returns the basic-block coverage hook switch passed to the plugin.
    #[must_use]
    pub const fn coverage(&self) -> QemuLaunchPluginSwitch {
        self.coverage
    }

    /// Returns the immutable app-random plan passed during setup.
    #[must_use]
    pub fn app_random_branch_plan(
        &self,
    ) -> &crucible_protocol::app_random_branch_plan::AppRandomBranchPlan {
        match &self.app_random {
            Some(config) => config.branch_plan(),
            None => empty_app_random_branch_plan(),
        }
    }

    /// Returns the immutable guest-selectable catalog plan passed during setup.
    #[must_use]
    pub fn selectable_catalog_plan(
        &self,
    ) -> &crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan {
        match &self.selectable_catalog_plan {
            Some(plan) => plan,
            None => empty_selectable_catalog_plan(),
        }
    }

    /// Returns the complete process-neutral plugin setup plan.
    #[must_use]
    pub fn plugin_setup_plan(&self) -> crucible_protocol::plugin_setup_plan::PluginSetupPlan {
        crucible_protocol::plugin_setup_plan::PluginSetupPlan::new(
            self.app_random_branch_plan().clone(),
            self.selectable_catalog_plan().clone(),
        )
    }

    /// Returns the single-VM fingerprint sampling switch passed to the plugin.
    #[must_use]
    pub const fn fingerprint(&self) -> QemuLaunchPluginSwitch {
        self.fingerprint
    }

    /// Returns the gate-only synchronous fingerprint-oracle switch.
    #[must_use]
    pub const fn fingerprint_oracle(&self) -> QemuLaunchPluginSwitch {
        self.fingerprint_oracle
    }

    /// Returns the fixed inherited setup descriptors.
    #[must_use]
    pub const fn inherited_fds(&self) -> QemuLaunchInheritedFds {
        QemuLaunchInheritedFds {
            shmem_fd: FIXED_PLUGIN_SHMEM_FD,
            wake_fd: FIXED_PLUGIN_WAKE_FD,
        }
    }

    /// Returns the raw plugin argument string passed after the plugin path.
    #[must_use]
    pub fn plugin_args_raw(&self) -> String {
        let mut args = vec![
            format!("{PLUGIN_ARG_SIMFD}={FIXED_PLUGIN_SIM_FD}"),
            format!("{PLUGIN_ARG_SLOT}={}", self.slot),
            format!(
                "{PLUGIN_ARG_FAULT_NODE_HASH}={}",
                lowercase_hex(&self.fault_node_hash)
            ),
            format!(
                "{PLUGIN_ARG_PROCESS_GENERATION}={}",
                self.process_generation
            ),
            format!(
                "{PLUGIN_ARG_NETWORK_TX_NEXT_SEQ}={}",
                self.network_tx_next_seq
            ),
            format!(
                "{PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS}={}",
                self.storage_completed_history_epochs
            ),
            format!(
                "{PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_GAPS}={}",
                self.storage_completed_history_gaps
            ),
            format!("{PLUGIN_ARG_SHMEMFD}={FIXED_PLUGIN_SHMEM_FD}"),
            format!("{PLUGIN_ARG_WAKEFD}={FIXED_PLUGIN_WAKE_FD}"),
            format!("{PLUGIN_ARG_WHITEBOX}={}", self.whitebox),
            format!("{PLUGIN_ARG_COVERAGE}={}", self.coverage),
        ];
        if self.whitebox == QemuLaunchPluginSwitch::On
            && let Some(validation) = self.whitebox_setup.as_ref()
        {
            args.push(format!(
                "{PLUGIN_ARG_WHITEBOX_SETUP}={}",
                validation.attestation()
            ));
        }
        if let Some(app_random) = &self.app_random {
            args.push(format!(
                "{PLUGIN_ARG_APP_RANDOM_SEED}={}",
                app_random.decision_rng_root_seed
            ));
            args.push(format!(
                "{PLUGIN_ARG_APP_RANDOM_CAP}={}",
                app_random.draw_cap
            ));
            args.push(format!(
                "{PLUGIN_ARG_APP_RANDOM_NODE}={}",
                app_random.node_name
            ));
            if let (Some(branch_seed), Some(branch_after)) = (
                app_random.branch_decision_rng_root_seed,
                app_random.branch_after_draws,
            ) {
                args.push(format!("{PLUGIN_ARG_APP_RANDOM_BRANCH_SEED}={branch_seed}"));
                args.push(format!(
                    "{PLUGIN_ARG_APP_RANDOM_BRANCH_AFTER}={branch_after}"
                ));
            }
            if app_random.draw_offset != 0 {
                args.push(format!(
                    "{PLUGIN_ARG_APP_RANDOM_DRAW_OFFSET}={}",
                    app_random.draw_offset
                ));
            }
            if !app_random.stream_positions.is_empty() {
                args.push(format!(
                    "{PLUGIN_ARG_APP_RANDOM_POSITIONS}={}",
                    encode_stream_positions(&app_random.stream_positions)
                ));
            }
        }
        // Emit fingerprint only when enabled so the disabled default keeps a
        // byte-identical argv to the pre-fingerprint ABI (the plugin parser
        // treats an absent fingerprint key as off).
        if self.fingerprint == QemuLaunchPluginSwitch::On {
            args.push(format!("{PLUGIN_ARG_FINGERPRINT}={}", self.fingerprint));
        }
        if self.fingerprint_oracle == QemuLaunchPluginSwitch::On {
            args.push(format!(
                "{PLUGIN_ARG_FINGERPRINT_ORACLE}={}",
                self.fingerprint_oracle
            ));
        }
        if let Some((target_icount, output_path)) = &self.state_dump {
            args.push(format!("{PLUGIN_ARG_STATE_DUMP_TARGET}={target_icount}"));
            args.push(format!("{PLUGIN_ARG_STATE_DUMP_PATH}={output_path}"));
        }
        args.join(",")
    }

    /// Returns the complete QEMU `-plugin` option value.
    #[must_use]
    pub fn qemu_plugin_argument(&self) -> String {
        format!("{},{}", self.plugin_path, self.plugin_args_raw())
    }

    pub(super) fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_launch_text("plugin_path", &self.plugin_path)?;
        if self.plugin_path.contains(',') {
            return Err(QemuLaunchCommandError::PluginPathContainsComma);
        }
        validate_store_path("plugin_path", &self.plugin_path)?;
        validate_fd(PLUGIN_ARG_SIMFD, FIXED_PLUGIN_SIM_FD)?;
        validate_fd(PLUGIN_ARG_SHMEMFD, FIXED_PLUGIN_SHMEM_FD)?;
        validate_fd(PLUGIN_ARG_WAKEFD, FIXED_PLUGIN_WAKE_FD)?;
        if self.process_generation == 0 {
            return Err(QemuLaunchCommandError::ZeroProcessGeneration);
        }
        let hard = crucible::model::FaultResourceLimits::compiled_maximum();
        validate_plugin_resource_limit(
            PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_EPOCHS,
            self.storage_completed_history_epochs,
            hard.storage_completed_history_epochs,
        )?;
        validate_plugin_resource_limit(
            PLUGIN_ARG_STORAGE_COMPLETED_HISTORY_GAPS,
            self.storage_completed_history_gaps,
            hard.storage_completed_history_gaps,
        )?;
        match (self.whitebox, self.whitebox_setup.as_ref()) {
            (QemuLaunchPluginSwitch::Off, None) | (QemuLaunchPluginSwitch::On, Some(_)) => {}
            (QemuLaunchPluginSwitch::On, None) => {
                return Err(QemuLaunchCommandError::MissingWhiteboxSetupValidation);
            }
            (QemuLaunchPluginSwitch::Off, Some(_)) => {
                return Err(QemuLaunchCommandError::WhiteboxSetupValidationWhileDisabled);
            }
        }
        if self.selectable_catalog_plan.as_ref().is_some_and(|plan| {
            plan != &crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::default()
        }) && self.whitebox != QemuLaunchPluginSwitch::On
        {
            return Err(QemuLaunchCommandError::SelectableCatalogWhileWhiteboxDisabled);
        }
        if let Some(app_random) = &self.app_random {
            if self.whitebox != QemuLaunchPluginSwitch::On {
                return Err(QemuLaunchCommandError::AppRandomWhileWhiteboxDisabled);
            }
            validate_launch_text(PLUGIN_ARG_APP_RANDOM_NODE, &app_random.node_name)?;
            if app_random.node_name.contains(',') || app_random.node_name.contains('=') {
                return Err(QemuLaunchCommandError::InvalidAppRandomNodeName);
            }
            if app_random.branch_decision_rng_root_seed.is_some()
                != app_random.branch_after_draws.is_some()
                || app_random
                    .branch_after_draws
                    .is_some_and(|after| after > app_random.draw_cap)
            {
                return Err(QemuLaunchCommandError::InvalidAppRandomBranchConfiguration);
            }
            let position_draws = app_random
                .stream_positions
                .values()
                .try_fold(0_u64, |sum, draws| sum.checked_add(*draws));
            if app_random.draw_offset > app_random.draw_cap
                || position_draws != Some(app_random.draw_offset)
                || app_random
                    .branch_after_draws
                    .is_some_and(|after| after < app_random.draw_offset)
            {
                return Err(QemuLaunchCommandError::InvalidAppRandomContinuationConfiguration);
            }
            if app_random
                .branch_plan
                .entries()
                .iter()
                .any(|entry| {
                    entry.draw_index() >= app_random.draw_cap
                        || !crucible_protocol::app_random_transport::app_random_stream_name_belongs_to_node(
                            entry.stream_name(),
                            &app_random.node_name,
                        )
                })
            {
                return Err(QemuLaunchCommandError::InvalidAppRandomBranchConfiguration);
            }
        }
        if let Some((target_icount, output_path)) = &self.state_dump {
            if self.fingerprint != QemuLaunchPluginSwitch::On || *target_icount == 0 {
                return Err(QemuLaunchCommandError::InvalidStateDumpConfiguration);
            }
            validate_launch_text(PLUGIN_ARG_STATE_DUMP_PATH, output_path)?;
            if !output_path.starts_with('/')
                || output_path.contains(',')
                || output_path.contains('=')
            {
                return Err(QemuLaunchCommandError::InvalidStateDumpConfiguration);
            }
        }
        Ok(())
    }
}

fn empty_app_random_branch_plan()
-> &'static crucible_protocol::app_random_branch_plan::AppRandomBranchPlan {
    static EMPTY: std::sync::OnceLock<
        crucible_protocol::app_random_branch_plan::AppRandomBranchPlan,
    > = std::sync::OnceLock::new();
    EMPTY.get_or_init(Default::default)
}

fn empty_selectable_catalog_plan()
-> &'static crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan {
    static EMPTY: std::sync::OnceLock<
        crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan,
    > = std::sync::OnceLock::new();
    EMPTY.get_or_init(Default::default)
}

fn validate_plugin_resource_limit(
    field: &'static str,
    configured: u64,
    hard: u64,
) -> Result<(), QemuLaunchCommandError> {
    if configured != 0 && configured <= hard {
        Ok(())
    } else {
        Err(QemuLaunchCommandError::InvalidPluginResourceLimit {
            field,
            configured,
            hard,
        })
    }
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn encode_stream_positions(positions: &BTreeMap<String, u64>) -> String {
    positions
        .iter()
        .map(|(name, draws)| format!("{}:{draws}", hex_encode(name.as_bytes())))
        .collect::<Vec<_>>()
        .join(";")
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
#[path = "plugin_config/tests.rs"]
mod tests;
