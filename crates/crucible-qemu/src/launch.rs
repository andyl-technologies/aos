//! Deterministic QEMU launch profile construction.
//!
//! The launch profile is the Contract-A boundary where host-specific QEMU
//! defaults become explicit, content-addressed inputs. The module does not spawn
//! QEMU; it validates and serializes the deterministic argument subset that
//! later supervision code will pass to the child process.

mod canonical;
mod control_channels;
mod crucible_shmem_9p;
mod crucible_shmem_block;
mod crucible_shmem_network;
mod entropy;
mod modes;
mod validation;
mod whitebox_setup;

use std::fmt;

use canonical::{
    canonical_node_clock_skew_lines, canonical_node_icount_shift_lines, validate_icount_shift,
};
pub use control_channels::{QemuGdbstubChannelConfig, QemuQmpChannelConfig};
use crucible::{ContentHash, NodeClockSkew};
pub use crucible_shmem_9p::{
    CrucibleShmem9pDevice, CrucibleShmem9pFsdevBackend, DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID,
    DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID, DEFAULT_CRUCIBLE_SHMEM_9P_MOUNT_TAG,
};
pub use crucible_shmem_block::{
    CrucibleShmemBlockDevice, DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID, DEFAULT_CRUCIBLE_SHMEM_DRIVE_ID,
};
pub use crucible_shmem_network::{
    CrucibleShmemNetworkDevice, DEFAULT_CRUCIBLE_SHMEM_NETDEV_ID,
    DEFAULT_CRUCIBLE_SHMEM_NETWORK_DEVICE_ID, DEFAULT_CRUCIBLE_SHMEM_NETWORK_MAC,
};
use entropy::{GUEST_ENTROPY_FW_CFG_NAME, GUEST_ENTROPY_RNG_ID, GUEST_ENTROPY_SEED_FILE_NAME};
pub use entropy::{GuestEntropySeed, GuestEntropySeedFile};
pub use modes::{
    DiskImageMode, GuestBackingStateMode, GuestCoreContentMode, IcountShiftSetting, InputPolicy,
    MachineResetMode,
};
use thiserror::Error;
pub use validation::{
    LaunchProfileError, QemuPreSpawnLaunchValidation, QemuPreSpawnLaunchValidationError,
    validate_pre_spawn_qemu_launch_args,
};
use validation::{canonical_cpu_model, validate_accelerator, validate_fixed_text};
pub use whitebox_setup::{
    QemuWhiteboxSetupError, QemuWhiteboxSetupValidation, probe_x86_whitebox_setup,
    validate_x86_whitebox_hmp_mtree,
};

const DEFAULT_CPU_MODEL: &str = "qemu64,-rdrand,-rdseed";
const DEFAULT_MACHINE_TYPE: &str = "pc-q35-9.2";
const DEFAULT_MEMORY_MIB: u32 = 512;
const DEFAULT_ACCEL: &str = "sim,thread=single";
const SIM_OFF_ACCEL: &str = "tcg,thread=single";
const DEFAULT_RTC_EPOCH_UTC: &str = "2026-01-01T00:00:00";
const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 quiet";
const DEFAULT_SCENARIO_SEED: u64 = 0x0010_c001;
const DEFAULT_RUN_SEED: u64 = 0x0010_c001;
const DEFAULT_RR_SWITCH_QUANTUM: u64 = 4096;
const PLUGIN_ARG_SIMFD: &str = "simfd";
const PLUGIN_ARG_SLOT: &str = "slot";
const PLUGIN_ARG_SHMEMFD: &str = "shmemfd";
const PLUGIN_ARG_WAKEFD: &str = "wakefd";
const PLUGIN_ARG_WHITEBOX: &str = "whitebox";
const PLUGIN_ARG_WHITEBOX_SETUP: &str = "whitebox_setup";
const WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1: &str = "x86-port-00e7-unclaimed-v1";
const PLUGIN_ARG_COVERAGE: &str = "coverage";
const PLUGIN_ARG_FINGERPRINT: &str = "fingerprint";
const FIXED_PLUGIN_SIM_FD: i32 = 3;
const FIXED_PLUGIN_SHMEM_FD: i32 = 4;
const FIXED_PLUGIN_WAKE_FD: i32 = 5;
/// Fixed child descriptor number for the host/plugin control socket.
pub const QEMU_PLUGIN_CONTROL_FD: i32 = FIXED_PLUGIN_SIM_FD;
/// Fixed child descriptor number for the inherited shared-memory region.
pub const QEMU_PLUGIN_SHMEM_FD: i32 = FIXED_PLUGIN_SHMEM_FD;
/// Fixed child descriptor number for the inherited wake event descriptor.
pub const QEMU_PLUGIN_WAKE_FD: i32 = FIXED_PLUGIN_WAKE_FD;
const DEFAULT_ROOT_OVERLAY_FILE_NAME: &str = "crucible-root-overlay.qcow2";
const ROOT_DRIVE_ID: &str = "crucible-root0";
const ROOT_DEVICE_ID: &str = "crucible-root-device0";
const MAX_ICOUNT_SHIFT: u8 = 62;
const MAX_RR_SWITCH_QUANTUM: u64 = i32::MAX as u64;

/// A candidate QEMU launch profile before determinism validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchProfileCandidate {
    /// The requested QEMU CPU model string.
    pub cpu_model: String,
    /// The requested QEMU accelerator string.
    pub accelerator: String,
    /// The requested QEMU machine type.
    pub machine_type: String,
    /// The requested guest RAM size in mebibytes.
    pub memory_mib: u32,
    /// The requested number of virtual CPUs.
    pub smp_vcpus: u16,
    /// The requested icount shift setting.
    pub icount_shift: IcountShiftSetting,
    /// The fixed single-threaded round-robin switch quantum in node icount.
    pub rr_switch_quantum: u64,
    /// The UTC RTC epoch supplied to QEMU.
    pub rtc_epoch_utc: String,
    /// The QEMU RTC clock mode.
    pub rtc_clock: String,
    /// The guest kernel command line.
    pub kernel_cmdline: String,
    /// The scenario seed used to derive guest-visible firmware entropy.
    pub scenario_seed: u64,
    /// The run seed passed to QEMU's deterministic random path.
    pub run_seed: u64,
    /// The reset discipline for RAM and emulated devices.
    pub machine_reset: MachineResetMode,
    /// The backing-image write policy.
    pub disk_image_mode: DiskImageMode,
    /// The genesis backing-state identity policy.
    pub guest_backing_state: GuestBackingStateMode,
    /// The policy for whether core Crucible operation requires guest-injected content.
    pub guest_core_content: GuestCoreContentMode,
    /// The host interactive input policy.
    pub input_policy: InputPolicy,
}

impl Default for LaunchProfileCandidate {
    fn default() -> Self {
        Self {
            cpu_model: DEFAULT_CPU_MODEL.to_owned(),
            accelerator: DEFAULT_ACCEL.to_owned(),
            machine_type: DEFAULT_MACHINE_TYPE.to_owned(),
            memory_mib: DEFAULT_MEMORY_MIB,
            smp_vcpus: 1,
            icount_shift: IcountShiftSetting::Fixed(0),
            rr_switch_quantum: DEFAULT_RR_SWITCH_QUANTUM,
            rtc_epoch_utc: DEFAULT_RTC_EPOCH_UTC.to_owned(),
            rtc_clock: "vm".to_owned(),
            kernel_cmdline: DEFAULT_KERNEL_CMDLINE.to_owned(),
            scenario_seed: DEFAULT_SCENARIO_SEED,
            run_seed: DEFAULT_RUN_SEED,
            machine_reset: MachineResetMode::Deterministic,
            disk_image_mode: DiskImageMode::CopyOnWriteOverlay,
            guest_backing_state: GuestBackingStateMode::ByteIdenticalGenesis,
            guest_core_content: GuestCoreContentMode::HostSideOnly,
            input_policy: InputPolicy::NoInteractiveInput,
        }
    }
}

impl LaunchProfileCandidate {
    /// Returns a candidate with a different CPU model.
    #[must_use]
    pub fn with_cpu_model(mut self, cpu_model: impl Into<String>) -> Self {
        self.cpu_model = cpu_model.into();
        self
    }

    /// Returns a candidate with a different accelerator string.
    #[must_use]
    pub fn with_accelerator(mut self, accelerator: impl Into<String>) -> Self {
        self.accelerator = accelerator.into();
        self
    }

    /// Returns a candidate with a different machine type.
    #[must_use]
    pub fn with_machine_type(mut self, machine_type: impl Into<String>) -> Self {
        self.machine_type = machine_type.into();
        self
    }

    /// Returns a candidate with a different fixed guest RAM size.
    #[must_use]
    pub fn with_memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    /// Returns a candidate with a different vCPU count.
    #[must_use]
    pub fn with_smp_vcpus(mut self, smp_vcpus: u16) -> Self {
        self.smp_vcpus = smp_vcpus;
        self
    }

    /// Returns a candidate with a different icount shift setting.
    #[must_use]
    pub fn with_icount_shift(mut self, icount_shift: IcountShiftSetting) -> Self {
        self.icount_shift = icount_shift;
        self
    }

    /// Returns a candidate with a different RR switch quantum.
    #[must_use]
    pub fn with_rr_switch_quantum(mut self, rr_switch_quantum: u64) -> Self {
        self.rr_switch_quantum = rr_switch_quantum;
        self
    }

    /// Returns a candidate with a different RTC epoch.
    #[must_use]
    pub fn with_rtc_epoch_utc(mut self, rtc_epoch_utc: impl Into<String>) -> Self {
        self.rtc_epoch_utc = rtc_epoch_utc.into();
        self
    }

    /// Returns a candidate with a different RTC clock mode.
    #[must_use]
    pub fn with_rtc_clock(mut self, rtc_clock: impl Into<String>) -> Self {
        self.rtc_clock = rtc_clock.into();
        self
    }

    /// Returns a candidate with a different kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(mut self, kernel_cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = kernel_cmdline.into();
        self
    }

    /// Returns a candidate with a different scenario seed.
    #[must_use]
    pub fn with_scenario_seed(mut self, scenario_seed: u64) -> Self {
        self.scenario_seed = scenario_seed;
        self.run_seed = scenario_seed;
        self
    }

    /// Returns a candidate with a different deterministic run seed.
    #[must_use]
    pub fn with_run_seed(mut self, run_seed: u64) -> Self {
        self.run_seed = run_seed;
        self.scenario_seed = run_seed;
        self
    }

    /// Returns a candidate with a different machine-reset mode.
    #[must_use]
    pub fn with_machine_reset(mut self, machine_reset: MachineResetMode) -> Self {
        self.machine_reset = machine_reset;
        self
    }

    /// Returns a candidate with a different disk image mode.
    #[must_use]
    pub fn with_disk_image_mode(mut self, disk_image_mode: DiskImageMode) -> Self {
        self.disk_image_mode = disk_image_mode;
        self
    }

    /// Returns a candidate with a different genesis backing-state policy.
    #[must_use]
    pub fn with_guest_backing_state(mut self, guest_backing_state: GuestBackingStateMode) -> Self {
        self.guest_backing_state = guest_backing_state;
        self
    }

    /// Returns a candidate with a different guest core-content policy.
    #[must_use]
    pub fn with_guest_core_content(mut self, guest_core_content: GuestCoreContentMode) -> Self {
        self.guest_core_content = guest_core_content;
        self
    }

    /// Returns a candidate with a different input policy.
    #[must_use]
    pub fn with_input_policy(mut self, input_policy: InputPolicy) -> Self {
        self.input_policy = input_policy;
        self
    }

    /// Validates this candidate as a deterministic launch profile.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchProfileError`] when any field would leave host
    /// nondeterminism in the QEMU launch configuration.
    pub fn try_into_deterministic(self) -> Result<DeterministicLaunchProfile, LaunchProfileError> {
        let cpu_model = canonical_cpu_model(&self.cpu_model)?;
        validate_accelerator(&self.accelerator)?;
        validate_fixed_text("machine_type", &self.machine_type)?;
        if self.memory_mib == 0 {
            return Err(LaunchProfileError::MemorySizeZero);
        }
        if self.smp_vcpus == 0 {
            return Err(LaunchProfileError::SmpVcpuCountZero);
        }

        let icount_shift = match self.icount_shift {
            IcountShiftSetting::Fixed(shift) => validate_icount_shift(shift)?,
            IcountShiftSetting::Auto => return Err(LaunchProfileError::IcountShiftAuto),
        };
        if self.rr_switch_quantum == 0 {
            return Err(LaunchProfileError::RrSwitchQuantumZero);
        }
        if self.rr_switch_quantum > MAX_RR_SWITCH_QUANTUM {
            return Err(LaunchProfileError::RrSwitchQuantumTooLarge {
                quantum: self.rr_switch_quantum,
            });
        }

        validate_fixed_text("rtc_epoch_utc", &self.rtc_epoch_utc)?;
        validate_fixed_text("kernel_cmdline", &self.kernel_cmdline)?;
        if self.rtc_clock != "vm" {
            return Err(LaunchProfileError::RtcClockNotVm {
                clock: self.rtc_clock,
            });
        }
        if self.run_seed != self.scenario_seed {
            return Err(LaunchProfileError::RunSeedDiffersFromScenarioSeed {
                scenario_seed: self.scenario_seed,
                run_seed: self.run_seed,
            });
        }
        if self.machine_reset != MachineResetMode::Deterministic {
            return Err(LaunchProfileError::MachineResetNotDeterministic {
                mode: self.machine_reset,
            });
        }
        match (self.disk_image_mode, self.guest_backing_state) {
            (DiskImageMode::CopyOnWriteOverlay, GuestBackingStateMode::ByteIdenticalGenesis)
            | (DiskImageMode::NoBlockDevice, GuestBackingStateMode::NoBlockDevice) => {}
            (DiskImageMode::WritableBacking, _) => {
                return Err(LaunchProfileError::DiskImageMutatesBacking {
                    mode: self.disk_image_mode,
                });
            }
            (_, GuestBackingStateMode::HostMutableGenesis) => {
                return Err(LaunchProfileError::GuestBackingStateNotByteIdentical {
                    mode: self.guest_backing_state,
                });
            }
            _ => {
                return Err(LaunchProfileError::StorageModeMismatch {
                    disk: self.disk_image_mode,
                    backing: self.guest_backing_state,
                });
            }
        }
        if self.guest_core_content != GuestCoreContentMode::HostSideOnly {
            return Err(LaunchProfileError::GuestCoreContentRequired {
                mode: self.guest_core_content,
            });
        }
        if self.input_policy != InputPolicy::NoInteractiveInput {
            return Err(LaunchProfileError::InteractiveInputEnabled {
                policy: self.input_policy,
            });
        }

        Ok(DeterministicLaunchProfile {
            cpu_model,
            machine_type: self.machine_type,
            memory_mib: self.memory_mib,
            smp_vcpus: self.smp_vcpus,
            icount_shift,
            rr_switch_quantum: self.rr_switch_quantum,
            rtc_epoch_utc: self.rtc_epoch_utc,
            kernel_cmdline: self.kernel_cmdline,
            scenario_seed: self.scenario_seed,
            run_seed: self.run_seed,
            disk_image_mode: self.disk_image_mode,
            guest_backing_state: self.guest_backing_state,
            guest_core_content: self.guest_core_content,
            guest_entropy_seed: GuestEntropySeed::from_scenario_seed(self.scenario_seed),
        })
    }
}

/// A node-local icount shift declaration from scenario launch content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeIcountShift {
    /// The stable scenario node identifier.
    pub node_id: String,
    /// The node's fixed `-icount shift=N` value.
    pub shift: u8,
}

impl NodeIcountShift {
    /// Builds a node-local icount shift declaration.
    #[must_use]
    pub fn new(node_id: impl Into<String>, shift: u8) -> Self {
        Self {
            node_id: node_id.into(),
            shift,
        }
    }
}

/// A node-local guest-visible clock-skew declaration from scenario launch content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeClockSkewDeclaration {
    /// The stable scenario node identifier.
    pub node_id: String,
    /// The node's guest-visible clock-skew transform.
    pub skew: NodeClockSkew,
}

impl NodeClockSkewDeclaration {
    /// Builds a node-local guest-visible clock-skew declaration.
    #[must_use]
    pub fn new(node_id: impl Into<String>, skew: NodeClockSkew) -> Self {
        Self {
            node_id: node_id.into(),
            skew,
        }
    }
}

/// A validated QEMU launch command prepared for process spawning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchCommand {
    executable: String,
    args: Vec<String>,
    vm_hash_material: String,
    gdbstub: Option<QemuGdbstubChannelConfig>,
    qmp: Option<QemuQmpChannelConfig>,
    plugin_coverage: QemuLaunchPluginSwitch,
}

impl QemuLaunchCommand {
    /// Returns the executable name or path that will be invoked.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Returns the argv tail passed after the executable.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Returns the world-derived VM launch material paired with this command.
    #[must_use]
    pub fn vm_launch_hash_material(&self) -> &str {
        &self.vm_hash_material
    }

    /// Returns the optional debug gdbstub channel for this launch.
    #[must_use]
    pub const fn gdbstub_channel(&self) -> Option<&QemuGdbstubChannelConfig> {
        self.gdbstub.as_ref()
    }

    /// Returns the optional QMP machine-control channel for this launch.
    #[must_use]
    pub const fn qmp_channel(&self) -> Option<&QemuQmpChannelConfig> {
        self.qmp.as_ref()
    }

    /// Returns the registration-time coverage mode encoded in `-plugin`.
    #[must_use]
    pub const fn plugin_coverage(&self) -> QemuLaunchPluginSwitch {
        self.plugin_coverage
    }

    /// Appends one content-addressed observation-only QEMU plugin.
    ///
    /// This is used by loaded-QEMU gates that need an independent fingerprint
    /// observer alongside the production control plugin. The complete argument
    /// remains part of [`Self::command_line_hash_material`].
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError`] when the argument is unstable text,
    /// its shared-object prefix is not an AOS store path, or the extended argv
    /// fails deterministic pre-spawn validation.
    #[cfg(target_os = "linux")]
    pub(crate) fn with_observation_plugin(
        mut self,
        plugin_argument: impl Into<String>,
    ) -> Result<Self, QemuLaunchCommandError> {
        let plugin_argument = plugin_argument.into();
        validate_launch_text("observation_plugin_argument", &plugin_argument)?;
        let plugin_path = plugin_argument
            .split_once(',')
            .map_or(plugin_argument.as_str(), |(path, _arguments)| path);
        validate_store_path("observation_plugin_path", plugin_path)?;
        self.args.extend(["-plugin".to_owned(), plugin_argument]);
        validate_pre_spawn_qemu_launch_args(&self.args)
            .map_err(|source| QemuLaunchCommandError::PreSpawnValidation { source })?;
        Ok(self)
    }

    /// Returns canonical material for hashing the complete QEMU command line.
    #[must_use]
    pub fn command_line_hash_material(&self) -> String {
        let mut lines = Vec::with_capacity(self.args.len() + 3);
        lines.push("crucible.qemu-launch-command.v1".to_owned());
        lines.push("command_line_in_hash=executable-and-argv".to_owned());
        lines.push(format!("executable={}", self.executable));
        for (index, argument) in self.args.iter().enumerate() {
            lines.push(format!("argv[{index}]={argument}"));
        }
        lines.join("\n")
    }
}

/// Builds the concrete QEMU launch command from a deterministic profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchCommandBuilder {
    profile: DeterministicLaunchProfile,
    vm: QemuVmLaunchConfig,
    executable: String,
    plugin: QemuLaunchPluginConfig,
    gdbstub: Option<QemuGdbstubChannelConfig>,
    qmp: Option<QemuQmpChannelConfig>,
}

impl QemuLaunchCommandBuilder {
    /// Builds a command builder for the supplied profile, VM, tools, and plugin config.
    #[must_use]
    pub fn new(
        profile: DeterministicLaunchProfile,
        vm: QemuVmLaunchConfig,
        executable: impl Into<String>,
        plugin: QemuLaunchPluginConfig,
    ) -> Self {
        Self {
            profile,
            vm,
            executable: executable.into(),
            plugin,
            gdbstub: None,
            qmp: None,
        }
    }

    /// Returns a builder that enables the debug-session gdbstub channel.
    #[must_use]
    pub fn with_gdbstub(mut self, gdbstub: QemuGdbstubChannelConfig) -> Self {
        self.gdbstub = Some(gdbstub);
        self
    }

    /// Returns a builder that enables the QMP machine-control channel.
    #[must_use]
    pub fn with_qmp(mut self, qmp: QemuQmpChannelConfig) -> Self {
        self.qmp = Some(qmp);
        self
    }

    /// Builds and validates the concrete QEMU command.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError`] when the executable or plugin launch
    /// fields are not stable command-line text, an immutable input is not an
    /// AOS store path, or the resulting argv fails the pre-spawn determinism
    /// validator.
    pub fn build(self) -> Result<QemuLaunchCommand, QemuLaunchCommandError> {
        validate_store_path("qemu_executable", &self.executable)?;
        self.vm.validate()?;
        self.plugin.validate()?;
        if let Some(gdbstub) = &self.gdbstub {
            gdbstub.validate()?;
        }
        if let Some(qmp) = &self.qmp {
            qmp.validate()?;
        }

        let vm_hash_material = self.vm.launch_hash_material();
        let mut args = self.profile.canonical_qemu_args();
        args.extend(self.vm.qemu_args());
        args.extend(["-plugin".to_owned(), self.plugin.qemu_plugin_argument()]);
        if let Some(qmp) = &self.qmp {
            args.extend(["-qmp".to_owned(), qmp.qemu_endpoint()]);
        }
        if let Some(gdbstub) = &self.gdbstub {
            args.extend(["-gdb".to_owned(), gdbstub.qemu_endpoint().to_owned()]);
        }
        validate_pre_spawn_qemu_launch_args(&args)
            .map_err(|source| QemuLaunchCommandError::PreSpawnValidation { source })?;

        Ok(QemuLaunchCommand {
            executable: self.executable,
            args,
            vm_hash_material,
            gdbstub: self.gdbstub,
            qmp: self.qmp,
            plugin_coverage: self.plugin.coverage(),
        })
    }
}

/// An immutable launch artifact resolved from a content-addressed world entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchArtifact {
    content_hash: ContentHash,
    path: String,
}

impl QemuLaunchArtifact {
    /// Builds an immutable launch artifact from its content hash and AOS store path.
    #[must_use]
    pub fn new(content_hash: ContentHash, path: impl Into<String>) -> Self {
        Self {
            content_hash,
            path: path.into(),
        }
    }

    /// Returns the artifact's content hash.
    #[must_use]
    pub const fn content_hash(&self) -> ContentHash {
        self.content_hash
    }

    /// Returns the materialized AOS store path passed to QEMU.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    fn validate(&self, field: &'static str) -> Result<(), QemuLaunchCommandError> {
        validate_store_path(field, &self.path)
    }
}

/// VM launch inputs derived from one static `World` VM node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuVmLaunchConfig {
    node_id: String,
    kernel: QemuLaunchArtifact,
    root_image: Option<QemuLaunchArtifact>,
    firmware: Option<QemuLaunchArtifact>,
    initrd: Option<QemuLaunchArtifact>,
    root_overlay_file_name: String,
    crucible_shmem_block: Option<CrucibleShmemBlockDevice>,
    crucible_shmem_9p: Option<CrucibleShmem9pDevice>,
    crucible_shmem_network: Option<CrucibleShmemNetworkDevice>,
}

impl QemuVmLaunchConfig {
    /// Builds a VM launch config from content-addressed kernel and root-image inputs.
    #[must_use]
    pub fn new(
        node_id: impl Into<String>,
        kernel: QemuLaunchArtifact,
        root_image: QemuLaunchArtifact,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            kernel,
            root_image: Some(root_image),
            firmware: None,
            initrd: None,
            root_overlay_file_name: DEFAULT_ROOT_OVERLAY_FILE_NAME.to_owned(),
            crucible_shmem_block: None,
            crucible_shmem_9p: None,
            crucible_shmem_network: None,
        }
    }

    /// Builds a diskless VM launch config that boots firmware, kernel, and initrd.
    ///
    /// A diskless launch attaches no block device, so a guest that would probe a
    /// virtio-blk root disk during boot never issues block I/O that a runner
    /// without a host block-I/O runtime cannot service.
    #[must_use]
    pub fn new_diskless(
        node_id: impl Into<String>,
        kernel: QemuLaunchArtifact,
        firmware: QemuLaunchArtifact,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            kernel,
            root_image: None,
            firmware: Some(firmware),
            initrd: None,
            root_overlay_file_name: DEFAULT_ROOT_OVERLAY_FILE_NAME.to_owned(),
            crucible_shmem_block: None,
            crucible_shmem_9p: None,
            crucible_shmem_network: None,
        }
    }

    /// Returns a config with a content-addressed initrd.
    #[must_use]
    pub fn with_initrd(mut self, initrd: QemuLaunchArtifact) -> Self {
        self.initrd = Some(initrd);
        self
    }

    /// Returns a config with a pinned content-addressed guest firmware image.
    #[must_use]
    pub fn with_firmware(mut self, firmware: QemuLaunchArtifact) -> Self {
        self.firmware = Some(firmware);
        self
    }

    /// Returns a config with a different stable root overlay file name.
    #[must_use]
    pub fn with_root_overlay_file_name(mut self, file_name: impl Into<String>) -> Self {
        self.root_overlay_file_name = file_name.into();
        self
    }

    /// Returns a config that attaches a crucible-shmem virtio-blk device.
    ///
    /// The device is opened through the legacy `-drive driver=crucible-shmem`
    /// interface and backed by the host I/O sub-node over the `SLOT_BLK_IO`
    /// shared-memory rings. A config without one emits byte-identical argv.
    #[must_use]
    pub fn with_crucible_shmem_block(mut self, device: CrucibleShmemBlockDevice) -> Self {
        self.crucible_shmem_block = Some(device);
        self
    }

    /// Returns the attached crucible-shmem block device, if any.
    #[must_use]
    pub const fn crucible_shmem_block(&self) -> Option<&CrucibleShmemBlockDevice> {
        self.crucible_shmem_block.as_ref()
    }

    /// Returns a config that attaches a crucible-shmem virtio-9p device.
    ///
    /// The device is a stock virtio-9p front-end whose PDUs the carried QEMU
    /// patch forwards to the host 9p servicer over the `SLOT_9P_IO` shared-memory
    /// rings. A config without one emits byte-identical argv.
    #[must_use]
    pub fn with_crucible_shmem_9p(mut self, device: CrucibleShmem9pDevice) -> Self {
        self.crucible_shmem_9p = Some(device);
        self
    }

    /// Returns the attached crucible-shmem 9p device, if any.
    #[must_use]
    pub const fn crucible_shmem_9p(&self) -> Option<&CrucibleShmem9pDevice> {
        self.crucible_shmem_9p.as_ref()
    }

    /// Returns a config that attaches a hostless Crucible virtio-net device.
    ///
    /// The loaded plugin intercepts guest TX and delivers scheduled RX through
    /// shared-memory rings. The QEMU hub port has no external backend.
    #[must_use]
    pub fn with_crucible_shmem_network(mut self, device: CrucibleShmemNetworkDevice) -> Self {
        self.crucible_shmem_network = Some(device);
        self
    }

    /// Returns the attached Crucible network device, if any.
    #[must_use]
    pub const fn crucible_shmem_network(&self) -> Option<&CrucibleShmemNetworkDevice> {
        self.crucible_shmem_network.as_ref()
    }

    /// Returns the static scenario node identifier.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Returns the content-addressed kernel artifact.
    #[must_use]
    pub const fn kernel(&self) -> &QemuLaunchArtifact {
        &self.kernel
    }

    /// Returns the content-addressed root-image artifact, if the launch has a disk.
    #[must_use]
    pub const fn root_image(&self) -> Option<&QemuLaunchArtifact> {
        self.root_image.as_ref()
    }

    /// Returns the pinned content-addressed firmware artifact, if any.
    #[must_use]
    pub const fn firmware(&self) -> Option<&QemuLaunchArtifact> {
        self.firmware.as_ref()
    }

    /// Returns the optional content-addressed initrd artifact.
    #[must_use]
    pub const fn initrd(&self) -> Option<&QemuLaunchArtifact> {
        self.initrd.as_ref()
    }

    /// Returns canonical world-derived launch material for scenario identity.
    #[must_use]
    pub fn launch_hash_material(&self) -> String {
        let mut lines = vec![
            "crucible.qemu-vm-launch.v1".to_owned(),
            format!("node_id={}", self.node_id),
            format!("kernel_hash={}", content_hash_hex(self.kernel.content_hash)),
            format!("kernel_path={}", self.kernel.path),
        ];
        if let Some(firmware) = &self.firmware {
            lines.push(format!(
                "firmware_hash={}",
                content_hash_hex(firmware.content_hash)
            ));
            lines.push(format!("firmware_path={}", firmware.path));
        }
        match &self.root_image {
            Some(root_image) => {
                lines.push(format!(
                    "root_image_hash={}",
                    content_hash_hex(root_image.content_hash)
                ));
                lines.push(format!("root_image_path={}", root_image.path));
                lines.push("root_disk_policy=copy-on-write-overlay".to_owned());
                lines.push(format!("root_overlay_file={}", self.root_overlay_file_name));
                lines.push(format!("root_drive_id={ROOT_DRIVE_ID}"));
                lines.push(format!("root_device_id={ROOT_DEVICE_ID}"));
                lines.push("root_device_model=virtio-blk-pci".to_owned());
            }
            None => lines.push("root_disk_policy=diskless".to_owned()),
        }
        if let Some(initrd) = &self.initrd {
            lines.push(format!(
                "initrd_hash={}",
                content_hash_hex(initrd.content_hash)
            ));
            lines.push(format!("initrd_path={}", initrd.path));
        } else {
            lines.push("initrd=none".to_owned());
        }
        // Emitted only when a device is attached: a launch without one keeps a
        // byte-identical identity string, so the frozen fingerprint gates that
        // never attach a crucible-shmem device do not drift.
        if let Some(device) = &self.crucible_shmem_block {
            device.append_hash_material(&mut lines);
        }
        if let Some(device) = &self.crucible_shmem_9p {
            device.append_hash_material(&mut lines);
        }
        if let Some(device) = &self.crucible_shmem_network {
            device.append_hash_material(&mut lines);
        }
        lines.join("\n")
    }

    fn qemu_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Some(firmware) = &self.firmware {
            args.extend(["-bios".to_owned(), firmware.path.clone()]);
        }
        args.extend(["-kernel".to_owned(), self.kernel.path.clone()]);
        if let Some(root_image) = &self.root_image {
            args.extend([
                "-drive".to_owned(),
                format!(
                    "id={ROOT_DRIVE_ID},file={},backing.driver=qcow2,backing.file.driver=file,backing.file.filename={},if=none,format=qcow2,cache=none,aio=threads,discard=unmap",
                    self.root_overlay_file_name, root_image.path
                ),
                "-device".to_owned(),
                format!("virtio-blk-pci,drive={ROOT_DRIVE_ID},id={ROOT_DEVICE_ID}"),
            ]);
        }
        if let Some(initrd) = &self.initrd {
            args.extend(["-initrd".to_owned(), initrd.path.clone()]);
        }
        if let Some(device) = &self.crucible_shmem_block {
            device.append_qemu_args(&mut args);
        }
        if let Some(device) = &self.crucible_shmem_9p {
            device.append_qemu_args(&mut args);
        }
        if let Some(device) = &self.crucible_shmem_network {
            device.append_qemu_args(&mut args);
        }
        args
    }

    fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_launch_text("node_id", &self.node_id)?;
        self.kernel.validate("kernel_path")?;
        if let Some(firmware) = &self.firmware {
            firmware.validate("firmware_path")?;
        }
        if let Some(root_image) = &self.root_image {
            root_image.validate("root_image_path")?;
            validate_overlay_file_name(&self.root_overlay_file_name)?;
        }
        if let Some(initrd) = &self.initrd {
            initrd.validate("initrd_path")?;
        }
        if let Some(device) = &self.crucible_shmem_block {
            device.validate()?;
        }
        if let Some(device) = &self.crucible_shmem_9p {
            device.validate()?;
        }
        if let Some(device) = &self.crucible_shmem_network {
            device.validate()?;
        }
        Ok(())
    }
}

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
    coverage: QemuLaunchPluginSwitch,
    fingerprint: QemuLaunchPluginSwitch,
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
            coverage: QemuLaunchPluginSwitch::Off,
            fingerprint: QemuLaunchPluginSwitch::Off,
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
        if self.whitebox == QemuLaunchPluginSwitch::On && self.whitebox_setup.is_some() {
            args.push(format!(
                "{PLUGIN_ARG_WHITEBOX_SETUP}={WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1}"
            ));
        }
        // Emit fingerprint only when enabled so the disabled default keeps a
        // byte-identical argv to the pre-fingerprint ABI (the plugin parser
        // treats an absent fingerprint key as off).
        if self.fingerprint == QemuLaunchPluginSwitch::On {
            args.push(format!("{PLUGIN_ARG_FINGERPRINT}={}", self.fingerprint));
        }
        args.join(",")
    }

    /// Returns the complete QEMU `-plugin` option value.
    #[must_use]
    pub fn qemu_plugin_argument(&self) -> String {
        format!("{},{}", self.plugin_path, self.plugin_args_raw())
    }

    fn validate(&self) -> Result<(), QemuLaunchCommandError> {
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
        Ok(())
    }
}

/// An error returned while building a QEMU launch command.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuLaunchCommandError {
    /// White-box mode lacked a live QEMU port-map validation.
    #[error("white-box QEMU launch requires live setup collision validation")]
    MissingWhiteboxSetupValidation,
    /// A white-box validation was attached while the callback was disabled.
    #[error("white-box setup validation is forbidden when white-box mode is off")]
    WhiteboxSetupValidationWhileDisabled,
    /// A command-line field was empty or could not be represented stably.
    #[error("{field} must be fixed non-empty text without newlines or NUL bytes")]
    InvalidLaunchText {
        /// Invalid command-line field.
        field: &'static str,
    },
    /// An immutable launch input was not resolved to an AOS store path.
    #[error("{field} must be an AOS store path, got `{path}`")]
    InvalidStorePath {
        /// Invalid immutable input field.
        field: &'static str,
        /// Invalid path.
        path: String,
    },
    /// The CoW overlay file name was not a stable relative file name.
    #[error("root overlay file name must be stable relative text, got `{file_name}`")]
    InvalidOverlayFileName {
        /// Invalid overlay file name.
        file_name: String,
    },
    /// The QMP socket file name was not a stable relative file name.
    #[error("QMP socket file name must be stable relative text, got `{file_name}`")]
    InvalidQmpSocketFileName {
        /// Invalid socket file name.
        file_name: String,
    },
    /// A crucible-shmem device length was zero, not a sector multiple, or too large.
    #[error(
        "crucible-shmem block size must be a nonzero sector multiple within bounds, got {size}"
    )]
    InvalidCrucibleShmemBlockSize {
        /// Rejected device length in bytes.
        size: u64,
    },
    /// A plugin path contained a comma, which would be ambiguous in QEMU's plugin option.
    #[error("plugin path must not contain a comma")]
    PluginPathContainsComma,
    /// A plugin descriptor was negative.
    #[error("plugin argument `{field}` has invalid descriptor {fd}")]
    InvalidFileDescriptor {
        /// Invalid descriptor field.
        field: &'static str,
        /// Invalid descriptor value.
        fd: i32,
    },
    /// The resulting argv failed the pre-spawn QEMU launch validator.
    #[error("QEMU launch command failed pre-spawn validation: {source}")]
    PreSpawnValidation {
        /// Validator error.
        source: QemuPreSpawnLaunchValidationError,
    },
}

/// A validated QEMU launch profile for Contract-A hermeticity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterministicLaunchProfile {
    cpu_model: String,
    machine_type: String,
    memory_mib: u32,
    smp_vcpus: u16,
    icount_shift: u8,
    rr_switch_quantum: u64,
    rtc_epoch_utc: String,
    kernel_cmdline: String,
    scenario_seed: u64,
    run_seed: u64,
    disk_image_mode: DiskImageMode,
    guest_backing_state: GuestBackingStateMode,
    guest_core_content: GuestCoreContentMode,
    guest_entropy_seed: GuestEntropySeed,
}

impl DeterministicLaunchProfile {
    /// Builds the conservative deterministic launch profile.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchProfileError`] if the checked-in default profile drifts
    /// away from the deterministic Contract-A requirements.
    pub fn conservative_default() -> Result<Self, LaunchProfileError> {
        LaunchProfileCandidate::default().try_into_deterministic()
    }

    /// Returns the QEMU arguments that pin the deterministic launch surface.
    #[must_use]
    pub fn canonical_qemu_args(&self) -> Vec<String> {
        self.canonical_qemu_args_with_accelerator(DEFAULT_ACCEL)
    }

    /// Returns stock-TCG arguments for sim-off inertness comparisons.
    ///
    /// This argument vector is not a valid Crucible runtime launch. It exists
    /// only to prove that the patched QEMU binary retains ordinary QEMU
    /// behavior when the TCG-derived `sim` accelerator is not selected.
    #[must_use]
    pub(crate) fn canonical_sim_off_qemu_args(&self) -> Vec<String> {
        self.canonical_qemu_args_with_accelerator(SIM_OFF_ACCEL)
    }

    fn canonical_qemu_args_with_accelerator(&self, accelerator: &str) -> Vec<String> {
        let seed_file = self.guest_entropy_seed_file();

        vec![
            "-nodefaults".to_owned(),
            "-no-user-config".to_owned(),
            "-display".to_owned(),
            "none".to_owned(),
            "-monitor".to_owned(),
            "none".to_owned(),
            "-serial".to_owned(),
            "none".to_owned(),
            "-parallel".to_owned(),
            "none".to_owned(),
            "-machine".to_owned(),
            self.machine_type.clone(),
            "-m".to_owned(),
            format!("{}M", self.memory_mib),
            "-accel".to_owned(),
            accelerator.to_owned(),
            "-cpu".to_owned(),
            self.cpu_model.clone(),
            "-smp".to_owned(),
            self.smp_vcpus.to_string(),
            "-icount".to_owned(),
            format!(
                "shift={},sleep=off,align=off,rr_switch_quantum={}",
                self.icount_shift, self.rr_switch_quantum
            ),
            "-rtc".to_owned(),
            format!("base={},clock=vm", self.rtc_epoch_utc),
            "-seed".to_owned(),
            self.run_seed.to_string(),
            "-fw_cfg".to_owned(),
            format!(
                "name={GUEST_ENTROPY_FW_CFG_NAME},file={}",
                seed_file.file_name()
            ),
            "-object".to_owned(),
            format!("rng-builtin,id={GUEST_ENTROPY_RNG_ID}"),
            "-device".to_owned(),
            format!("virtio-rng-pci,rng={GUEST_ENTROPY_RNG_ID}"),
            "-append".to_owned(),
            self.kernel_cmdline.clone(),
        ]
    }

    /// Builds a concrete QEMU launch command with the supplied plugin config.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError`] when command construction or final
    /// pre-spawn validation fails.
    pub fn qemu_launch_command(
        &self,
        vm: QemuVmLaunchConfig,
        executable: impl Into<String>,
        plugin: QemuLaunchPluginConfig,
    ) -> Result<QemuLaunchCommand, QemuLaunchCommandError> {
        QemuLaunchCommandBuilder::new(self.clone(), vm, executable, plugin).build()
    }

    /// Returns canonical material that must be included in the scenario hash.
    #[must_use]
    pub fn scenario_hash_material(&self) -> String {
        [
            "crucible.launch.v1".to_owned(),
            format!("cpu_model={}", self.cpu_model),
            format!("machine_type={}", self.machine_type),
            format!("memory_mib={}", self.memory_mib),
            format!("smp_vcpus={}", self.smp_vcpus),
            "vcpu_topology=fixed-at-genesis".to_owned(),
            "runtime_cpu_hotplug=forbidden".to_owned(),
            format!("accelerator={DEFAULT_ACCEL}"),
            "accelerator_family=tcg-derived-sim".to_owned(),
            "simulation_mode=on".to_owned(),
            "stock_tcg_crucible_runtime=forbidden".to_owned(),
            format!("icount_shift={}", self.icount_shift),
            format!("rr_switch_quantum={}", self.rr_switch_quantum),
            "rr_switch_quantum_units=node-icount".to_owned(),
            "rr_vcpu_rotation=ascending-vcpu-id".to_owned(),
            "virtual_time_ns=icount<<shift".to_owned(),
            "per_vcpu_cpu_model=uniform".to_owned(),
            "per_vcpu_tsc_source=node-icount".to_owned(),
            format!("rtc_epoch_utc={}", self.rtc_epoch_utc),
            "rtc_clock=vm".to_owned(),
            "guest_time_sources=rtc,tsc,timer-devices:icount-derived-virtual-time".to_owned(),
            "guest_time_epoch=fixed-rtc-epoch".to_owned(),
            "time_control_owner=crucible-qemu-plugin".to_owned(),
            "time_control_acquire=registration-before-first-visible-instruction".to_owned(),
            "idle_warp_under_time_control=suppressed".to_owned(),
            "icount_budget_deadline_source=QEMU_CLOCK_VIRTUAL".to_owned(),
            "realtime_deadline_in_precise_budget=false".to_owned(),
            "device_completion_delivery=synchronous-at-request-icount".to_owned(),
            "machine_reset=deterministic-zeroed-ram-fixed-devices".to_owned(),
            "ram_reset=zeroed-fresh-anonymous-memory".to_owned(),
            format!("disk_image_mode={}", self.disk_image_mode),
            format!("guest_write_policy={}", self.disk_image_mode),
            format!("guest_backing_state={}", self.guest_backing_state),
            "guest_on_disk_mutation_policy=forbidden-by-launch-profile".to_owned(),
            format!("guest_core_content={}", self.guest_core_content),
            "input_policy=no-interactive-input".to_owned(),
            format!("scenario_seed={}", self.scenario_seed),
            format!("qemu_run_seed={}", self.run_seed),
            "qemu_run_seed_controls=guest-random,glib-global-prng,rng-builtin".to_owned(),
            format!("guest_entropy_fw_cfg_name={GUEST_ENTROPY_FW_CFG_NAME}"),
            format!("guest_entropy_seed_file_name={GUEST_ENTROPY_SEED_FILE_NAME}"),
            "guest_entropy_seed_source=scenario-seed".to_owned(),
            format!(
                "guest_entropy_seed_hex={}",
                self.guest_entropy_seed.to_lower_hex()
            ),
            format!("guest_entropy_rng_object=rng-builtin,id={GUEST_ENTROPY_RNG_ID}"),
            format!("guest_entropy_rng_device=virtio-rng-pci,rng={GUEST_ENTROPY_RNG_ID}"),
            "guest_entropy_host_sources=disabled".to_owned(),
            "per_vcpu_rng_source=scenario-seed-and-run-seed".to_owned(),
            "per_vcpu_rng_timing_axis=node-icount".to_owned(),
            "secondary_vcpu_bringup=rr-sim-tcg-icount-deterministic".to_owned(),
            format!("kernel_cmdline={}", self.kernel_cmdline),
        ]
        .join("\n")
    }

    /// Returns scenario material that includes the complete QEMU command line.
    #[must_use]
    pub fn scenario_hash_material_for_launch_command(&self, command: &QemuLaunchCommand) -> String {
        let mut material = self.scenario_hash_material();
        material.push('\n');
        material.push_str(command.vm_launch_hash_material());
        material.push('\n');
        material.push_str(&command.command_line_hash_material());
        material
    }

    /// Returns canonical scenario hash material after validating node shifts.
    ///
    /// Node shift declarations are sorted by node identifier before they enter
    /// the material so callers do not have to preserve a host-dependent
    /// iteration order.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchProfileError`] when a node identifier is not stable text,
    /// a node is declared more than once, a node requests an unsupported fixed
    /// shift, or a node shift differs from the scenario-wide launch-profile
    /// shift.
    pub fn scenario_hash_material_for_nodes(
        &self,
        node_shifts: &[NodeIcountShift],
    ) -> Result<String, LaunchProfileError> {
        let node_shift_lines = canonical_node_icount_shift_lines(self.icount_shift, node_shifts)?;
        let mut material = self.scenario_hash_material();
        for line in node_shift_lines {
            material.push('\n');
            material.push_str(&line);
        }
        Ok(material)
    }

    /// Returns canonical scenario hash material after validating node timing declarations.
    ///
    /// Node declarations are sorted by node identifier before they enter the
    /// material so callers do not have to preserve a host-dependent iteration
    /// order. Perfect clock-skew declarations are omitted, making explicit
    /// perfect clocks byte-identical to no skew declarations.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchProfileError`] when a node identifier is not stable text,
    /// a node timing declaration is duplicated, a node shift is unsupported or
    /// mismatches the profile, or a node clock-skew declaration uses an invalid
    /// drift rate.
    pub fn scenario_hash_material_for_node_timing(
        &self,
        node_shifts: &[NodeIcountShift],
        node_clock_skews: &[NodeClockSkewDeclaration],
    ) -> Result<String, LaunchProfileError> {
        let node_shift_lines = canonical_node_icount_shift_lines(self.icount_shift, node_shifts)?;
        let node_skew_lines = canonical_node_clock_skew_lines(node_clock_skews)?;
        let mut material = self.scenario_hash_material();
        for line in node_shift_lines.into_iter().chain(node_skew_lines) {
            material.push('\n');
            material.push_str(&line);
        }
        Ok(material)
    }

    /// Returns the scenario seed used for guest entropy derivation.
    #[must_use]
    pub fn scenario_seed(&self) -> u64 {
        self.scenario_seed
    }

    /// Returns the deterministic firmware seed supplied to guest entropy.
    #[must_use]
    pub fn guest_entropy_seed(&self) -> GuestEntropySeed {
        self.guest_entropy_seed
    }

    /// Returns the seed-file artifact that must be materialized for QEMU.
    #[must_use]
    pub fn guest_entropy_seed_file(&self) -> GuestEntropySeedFile {
        GuestEntropySeedFile {
            file_name: GUEST_ENTROPY_SEED_FILE_NAME,
            bytes: *self.guest_entropy_seed.bytes(),
        }
    }

    /// Returns the exact guest kernel command line emitted through `-append`.
    #[must_use]
    pub fn kernel_cmdline(&self) -> &str {
        &self.kernel_cmdline
    }

    /// Returns the validated guest block-storage policy.
    #[must_use]
    pub const fn disk_image_mode(&self) -> DiskImageMode {
        self.disk_image_mode
    }

    /// Returns the validated guest backing-state policy.
    #[must_use]
    pub const fn guest_backing_state(&self) -> GuestBackingStateMode {
        self.guest_backing_state
    }

    /// Returns the fixed `-icount shift=N` value pinned by this launch profile.
    #[must_use]
    pub fn icount_shift(&self) -> u8 {
        self.icount_shift
    }

    /// Returns the fixed QEMU `-smp` vCPU count.
    #[must_use]
    pub fn smp_vcpus(&self) -> u16 {
        self.smp_vcpus
    }

    /// Returns the fixed single-threaded round-robin switch quantum.
    #[must_use]
    pub fn rr_switch_quantum(&self) -> u64 {
        self.rr_switch_quantum
    }

    /// Validates that every node launch declaration uses this profile's shift.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchProfileError`] when a node identifier is not stable text,
    /// a node is declared more than once, a node requests an unsupported fixed
    /// shift, or a node shift differs from the scenario-wide launch-profile
    /// shift.
    pub fn validate_node_icount_shifts(
        &self,
        node_shifts: &[NodeIcountShift],
    ) -> Result<(), LaunchProfileError> {
        validate_node_icount_shifts(self.icount_shift, node_shifts)
    }

    /// Converts an instruction count to virtual nanoseconds.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchProfileError::VirtualTimeOverflow`] when the configured
    /// shift would overflow `u64`.
    pub fn virtual_ns_from_icount(&self, icount: u64) -> Result<u64, LaunchProfileError> {
        let scale = 1_u64 << u32::from(self.icount_shift);
        icount
            .checked_mul(scale)
            .ok_or(LaunchProfileError::VirtualTimeOverflow {
                icount,
                shift: self.icount_shift,
            })
    }
}

fn validate_node_icount_shifts(
    scenario_shift: u8,
    node_shifts: &[NodeIcountShift],
) -> Result<(), LaunchProfileError> {
    canonical_node_icount_shift_lines(scenario_shift, node_shifts)?;
    Ok(())
}

fn validate_launch_text(field: &'static str, value: &str) -> Result<(), QemuLaunchCommandError> {
    if value.is_empty() || value.contains('\n') || value.contains('\0') {
        Err(QemuLaunchCommandError::InvalidLaunchText { field })
    } else {
        Ok(())
    }
}

fn validate_store_path(field: &'static str, path: &str) -> Result<(), QemuLaunchCommandError> {
    validate_launch_text(field, path)?;
    if path.starts_with("/nix/store/")
        && !path.contains("/../")
        && !path.ends_with("/..")
        && !path.contains("/./")
        && !path.ends_with("/.")
        && !path.contains('\\')
        && !path.contains(',')
    {
        Ok(())
    } else {
        Err(QemuLaunchCommandError::InvalidStorePath {
            field,
            path: path.to_owned(),
        })
    }
}

fn validate_overlay_file_name(file_name: &str) -> Result<(), QemuLaunchCommandError> {
    validate_launch_text("root_overlay_file_name", file_name)?;
    if file_name.contains('/') || file_name.contains('\\') || file_name.contains(',') {
        Err(QemuLaunchCommandError::InvalidOverlayFileName {
            file_name: file_name.to_owned(),
        })
    } else {
        Ok(())
    }
}

fn validate_fd(field: &'static str, fd: i32) -> Result<(), QemuLaunchCommandError> {
    if fd < 0 {
        Err(QemuLaunchCommandError::InvalidFileDescriptor { field, fd })
    } else {
        Ok(())
    }
}

fn content_hash_hex(hash: ContentHash) -> String {
    let mut hex = String::with_capacity(hash.bytes.len() * 2);
    for byte in hash.bytes {
        hex.push(nibble_to_hex(byte >> 4));
        hex.push(nibble_to_hex(byte & 0x0f));
    }
    hex
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!("nibble is masked to four bits"),
    }
}

// The launch-profile mode enums and their `Display` renderings live in the
// `modes` submodule and are re-exported above, next to the other launch types.
