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
    /// Small scenario seed used to reconstruct the authoritative host scenario.
    pub scenario_seed: u64,
    /// Derived L0 decision-RNG root consumed by the synchronous plugin adapter.
    pub decision_rng_root_seed: u64,
    /// Scenario-hashed maximum number of app-random draws.
    pub draw_cap: u64,
    /// Canonical scheduler node name used in the name-hashed stream identity.
    pub node_name: String,
}

impl QemuLaunchAppRandomConfig {
    /// Builds a complete live app-random launch configuration.
    #[must_use]
    pub fn new(root_seed: u64, draw_cap: u64, node_name: impl Into<String>) -> Self {
        Self {
            scenario_seed: root_seed,
            decision_rng_root_seed: Seed::from_u64(root_seed).decision_rng_root_seed(),
            draw_cap,
            node_name: node_name.into(),
        }
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
