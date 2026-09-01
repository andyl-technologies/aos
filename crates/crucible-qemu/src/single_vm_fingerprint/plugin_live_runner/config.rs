//! Immutable live fingerprint-runner launch inputs.

use super::*;

/// Immutable launch inputs shared by every run of one fingerprint scenario.
///
/// The QEMU and Rust plugin binaries are content-hashed at construction and the
/// resulting digests bind the fingerprint definition, so a stream produced
/// against a different QEMU or plugin build can never compare as equal.
#[derive(Clone, Debug)]
pub struct PluginFingerprintRunnerConfig {
    pub(super) qemu_executable: PathBuf,
    pub(super) plugin: PathBuf,
    pub(super) kernel: PathBuf,
    pub(super) firmware: PathBuf,
    pub(super) initrd: Option<PathBuf>,
    pub(super) run_directory: PathBuf,
    pub(super) kernel_cmdline: Option<String>,
    pub(super) completion_timeout: Duration,
    pub(super) second_run_scheduler_preemption: bool,
    pub(super) second_run_divergence_control: bool,
    pub(super) synchronous_oracle: bool,
    pub(super) qemu_build_digest: String,
    pub(super) rust_plugin_build_digest: String,
    pub(super) rr_switch_quantum: u64,
    pub(super) smp_vcpus: u16,
    pub(super) memory_mib: u32,
    pub(super) translation_prefetch_experiment: Option<bool>,
}

impl PluginFingerprintRunnerConfig {
    /// Builds a runner configuration, hashing the QEMU and plugin binaries.
    ///
    /// The diskless `firmware` selects the no-block-device launch shape the
    /// busy-boot cadence requires, mirroring the quantum gate.
    ///
    /// # Errors
    ///
    /// Returns [`PluginFingerprintRunnerError::ReadBuildArtifact`] when the QEMU
    /// executable or the plugin shared object cannot be read for hashing.
    pub fn new(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        firmware: impl Into<PathBuf>,
        run_directory: impl Into<PathBuf>,
    ) -> Result<Self, PluginFingerprintRunnerError> {
        let qemu_executable = qemu_executable.into();
        let plugin = plugin.into();
        let qemu_build_digest = hash_file(&qemu_executable)?;
        let rust_plugin_build_digest = hash_file(&plugin)?;
        Ok(Self {
            qemu_executable,
            plugin,
            kernel: kernel.into(),
            firmware: firmware.into(),
            initrd: None,
            run_directory: run_directory.into(),
            kernel_cmdline: None,
            completion_timeout: Duration::from_secs(240),
            second_run_scheduler_preemption: true,
            second_run_divergence_control: false,
            synchronous_oracle: false,
            qemu_build_digest,
            rust_plugin_build_digest,
            rr_switch_quantum: 0,
            smp_vcpus: DEFAULT_RUNNER_SMP_VCPUS,
            memory_mib: DEFAULT_RUNNER_MEMORY_MIB,
            translation_prefetch_experiment: None,
        })
    }

    /// Returns this configuration with a fixed guest memory size in MiB.
    ///
    /// Guest memory is a launch parameter only; it is not part of the
    /// fingerprint definition digest.
    #[must_use]
    pub const fn with_memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    /// Returns this configuration with a fixed vCPU count for the launch.
    ///
    /// The count is bound into both the launch `-smp` flag and the fingerprint
    /// definition digest (via [`RustPluginFingerprintDefinition`]), so a run at a
    /// different topology can never compare as equal. It must equal the vCPU
    /// count the scenario's N-vCPU contract declares.
    #[must_use]
    pub const fn with_smp_vcpus(mut self, smp_vcpus: u16) -> Self {
        self.smp_vcpus = smp_vcpus;
        self
    }

    /// Returns the launch-pinned vCPU count.
    #[must_use]
    pub const fn smp_vcpus(&self) -> u16 {
        self.smp_vcpus
    }

    /// Returns this configuration with a content-addressed initrd.
    #[must_use]
    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    /// Returns this configuration with an explicit guest kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(mut self, kernel_cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = Some(kernel_cmdline.into());
        self
    }

    /// Returns this configuration with a different host-side completion bound.
    #[must_use]
    pub const fn with_completion_timeout(mut self, completion_timeout: Duration) -> Self {
        self.completion_timeout = completion_timeout;
        self
    }

    /// Returns this configuration with bounded scheduler preemption on the second run toggled.
    #[must_use]
    pub const fn with_second_run_scheduler_preemption(
        mut self,
        second_run_scheduler_preemption: bool,
    ) -> Self {
        self.second_run_scheduler_preemption = second_run_scheduler_preemption;
        self
    }

    /// Enables a gate-only negative control that changes second-run live inputs.
    ///
    /// Production callers leave this disabled. Live acceptance tests enable it
    /// to vary the second launch's guest command line, delivered frame, and
    /// injected interrupt, forcing a real QEMU architectural divergence and
    /// exercising exact bisection plus both-side raw-state dumping end to end.
    #[must_use]
    pub const fn with_second_run_divergence_control(mut self, enabled: bool) -> Self {
        self.second_run_divergence_control = enabled;
        self
    }

    /// Enables gate-only comparison against the synchronous digest path.
    ///
    /// Production callers leave this disabled so all large component digests
    /// remain off the vCPU thread.
    #[must_use]
    pub const fn with_synchronous_oracle(mut self, enabled: bool) -> Self {
        self.synchronous_oracle = enabled;
        self
    }

    /// Returns this configuration with gate-only translation generation toggled.
    ///
    /// Ordinary launches leave this unset, which preserves byte-identical argv
    /// and keeps the experimental mechanism off. PERF-32 sets it to both
    /// `false` and `true` for otherwise identical cold-boot runs.
    #[must_use]
    pub const fn with_translation_prefetch_experiment(mut self, enabled: bool) -> Self {
        self.translation_prefetch_experiment = Some(enabled);
        self
    }

    /// Returns whether the gate-only synchronous digest oracle is enabled.
    #[must_use]
    pub const fn synchronous_oracle(&self) -> bool {
        self.synchronous_oracle
    }

    /// Returns the content digest of the pinned QEMU build.
    #[must_use]
    pub fn qemu_build_digest(&self) -> &str {
        &self.qemu_build_digest
    }

    /// Returns the content digest of the pinned Rust plugin build.
    #[must_use]
    pub fn rust_plugin_build_digest(&self) -> &str {
        &self.rust_plugin_build_digest
    }
}
