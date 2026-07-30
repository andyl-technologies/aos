//! Production plugin launch configuration and inherited descriptors.

use super::*;

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
    whitebox: QemuLaunchPluginSwitch,
    whitebox_setup: Option<QemuWhiteboxSetupValidation>,
    app_random: Option<QemuLaunchAppRandomConfig>,
    coverage: QemuLaunchPluginSwitch,
    fingerprint: QemuLaunchPluginSwitch,
    fingerprint_oracle: QemuLaunchPluginSwitch,
    state_dump: Option<(u64, String)>,
}

impl QemuLaunchPluginConfig {
    /// Builds the required plugin launch config.
    #[must_use]
    pub fn new(plugin_path: impl Into<String>, slot: u32) -> Self {
        Self {
            plugin_path: plugin_path.into(),
            slot,
            whitebox: QemuLaunchPluginSwitch::Off,
            whitebox_setup: None,
            app_random: None,
            coverage: QemuLaunchPluginSwitch::Off,
            fingerprint: QemuLaunchPluginSwitch::Off,
            fingerprint_oracle: QemuLaunchPluginSwitch::Off,
            state_dump: None,
        }
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
        match (self.whitebox, self.whitebox_setup.as_ref()) {
            (QemuLaunchPluginSwitch::Off, None) | (QemuLaunchPluginSwitch::On, Some(_)) => {}
            (QemuLaunchPluginSwitch::On, None) => {
                return Err(QemuLaunchCommandError::MissingWhiteboxSetupValidation);
            }
            (QemuLaunchPluginSwitch::Off, Some(_)) => {
                return Err(QemuLaunchCommandError::WhiteboxSetupValidationWhileDisabled);
            }
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
mod tests {
    use super::*;

    #[test]
    fn complete_scenario_seed_controls_the_plugin_decision_root() {
        let mut first = [0_u8; 32];
        first[..8].copy_from_slice(&11_u64.to_le_bytes());
        let mut second = first;
        second[31] = 1;

        let first = QemuLaunchAppRandomConfig::from_seed(Seed::from_bytes(first), 8, "a");
        let second = QemuLaunchAppRandomConfig::from_seed(Seed::from_bytes(second), 8, "a");

        assert_eq!(first.scenario_seed, second.scenario_seed);
        assert_ne!(first.authoritative_seed(), second.authoritative_seed());
        assert_ne!(first.decision_rng_root_seed, second.decision_rng_root_seed);
    }

    #[test]
    fn app_random_branch_and_continuation_arguments_are_canonical() {
        let positions = BTreeMap::from([
            (String::from("app-random/node:1:a/stream:4:beta"), 1),
            (String::from("app-random/node:1:a/stream:5:alpha"), 2),
        ]);
        let app_random = QemuLaunchAppRandomConfig::new(11, 8, "a")
            .with_branch_reseed(29, 3)
            .with_continuation(3, positions.clone());
        assert_eq!(app_random.branch_seed(), Some(Seed::from_u64(29)));
        let arguments = QemuLaunchPluginConfig::new("/nix/store/plugin.so", 0)
            .with_whitebox(QemuLaunchPluginSwitch::On)
            .with_app_random(app_random)
            .plugin_args_raw();

        assert!(arguments.contains(&format!(
            "app_random_branch_seed={}",
            Seed::from_u64(29).decision_rng_root_seed()
        )));
        assert!(arguments.contains("app_random_branch_after=3"));
        assert!(arguments.contains("app_random_draw_offset=3"));
        assert!(arguments.contains(&format!(
            "app_random_positions={}",
            encode_stream_positions(&positions)
        )));
        assert_eq!(
            encode_stream_positions(&positions),
            "6170702d72616e646f6d2f6e6f64653a313a612f73747265616d3a343a62657461:1;\
             6170702d72616e646f6d2f6e6f64653a313a612f73747265616d3a353a616c706861:2"
        );
    }
}
