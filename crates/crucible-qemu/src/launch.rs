//! Deterministic QEMU launch profile construction.
//!
//! The launch profile is the Contract-A boundary where host-specific QEMU
//! defaults become explicit, content-addressed inputs. The module does not spawn
//! QEMU; it validates and serializes the deterministic argument subset that
//! later supervision code will pass to the child process.

mod canonical;
mod control_channels;
mod crucible_accelerator;
mod crucible_shmem_9p;
mod crucible_shmem_block;
mod crucible_shmem_network;
mod entropy;
mod error;
mod helpers;
mod modes;
mod plugin_config;
mod validation;
mod whitebox_setup;

use std::collections::BTreeMap;
use std::fmt;

use canonical::{canonical_node_icount_shift_lines, validate_icount_shift};
pub use control_channels::{QemuGdbstubChannelConfig, QemuQmpChannelConfig};
use crucible::{ContentHash, SchedulerError, SchedulerNodeId, SchedulerRunSubdivisionPolicy, Seed};
pub use crucible_accelerator::{CrucibleAcceleratorDevice, DEFAULT_CRUCIBLE_ACCELERATOR_DEVICE_ID};
pub use crucible_shmem_9p::{
    CrucibleShmem9pDevice, CrucibleShmem9pFsdevBackend, DEFAULT_CRUCIBLE_SHMEM_9P_DEVICE_ID,
    DEFAULT_CRUCIBLE_SHMEM_9P_FSDEV_ID, DEFAULT_CRUCIBLE_SHMEM_9P_MOUNT_TAG,
};
pub use crucible_shmem_block::{
    CrucibleShmemBlockDevice, DEFAULT_CRUCIBLE_SHMEM_BLOCK_NODE_NAME,
    DEFAULT_CRUCIBLE_SHMEM_DEVICE_ID,
};
pub use crucible_shmem_network::{
    CrucibleShmemNetworkDevice, DEFAULT_CRUCIBLE_SHMEM_NETDEV_ID,
    DEFAULT_CRUCIBLE_SHMEM_NETWORK_DEVICE_ID, DEFAULT_CRUCIBLE_SHMEM_NETWORK_MAC,
};
use entropy::{GUEST_ENTROPY_FW_CFG_NAME, GUEST_ENTROPY_RNG_ID, GUEST_ENTROPY_SEED_FILE_NAME};
pub use entropy::{GuestEntropySeed, GuestEntropySeedFile};
pub use error::{QemuLaunchCommandError, QemuLaunchResourceError};
use helpers::{
    content_hash_hex, validate_fd, validate_launch_text, validate_node_icount_shifts,
    validate_overlay_file_name, validate_store_path,
};
pub use modes::{
    DiskImageMode, GuestBackingStateMode, GuestCoreContentMode, IcountShiftSetting, InputPolicy,
    MachineResetMode,
};
pub use plugin_config::{
    QemuLaunchAppRandomConfig, QemuLaunchInheritedFds, QemuLaunchPluginConfig,
    QemuLaunchPluginSwitch,
};
pub use validation::{
    LaunchProfileError, QemuPreSpawnLaunchValidation, QemuPreSpawnLaunchValidationError,
    validate_pre_spawn_qemu_launch_args,
};
use validation::{canonical_cpu_model, validate_accelerator, validate_fixed_text};
#[cfg(target_os = "linux")]
pub(crate) use whitebox_setup::probe_x86_whitebox_setup_guarded;
pub use whitebox_setup::{
    QemuWhiteboxSetupError, QemuWhiteboxSetupValidation, probe_x86_whitebox_setup,
    validate_aarch64_whitebox_setup, validate_x86_whitebox_hmp_mtree,
};

/// Stable QEMU chardev identifier for output-only guest console capture.
pub const QEMU_CONSOLE_CHARDEV_ID: &str = "crucible-console";
/// Stable run-directory Unix socket carrying output-only guest console bytes.
pub const QEMU_CONSOLE_SOCKET_FILE_NAME: &str = "crucible-console.sock";
/// Stable QEMU chardev identifier for fork-time debug guest activation.
pub const QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID: &str = "crucible-debug-activation";
/// Stable run-directory socket used to inject the fork-time activation token.
pub const QEMU_DEBUG_GUEST_ACTIVATION_SOCKET_FILE_NAME: &str = "crucible-debug-activation.sock";
/// Stable virtio-serial controller identifier for debugger-only guest channels.
pub const QEMU_DEBUG_GUEST_VIRTIO_SERIAL_ID: &str = "crucible-debug-serial";
/// Stable guest-visible virtio-port name for the dormant debugger bootstrap.
pub const QEMU_DEBUG_GUEST_ACTIVATION_PORT_NAME: &str = "org.aos.crucible.debug";

/// Guest architecture selected by a deterministic QEMU launch profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LivePluginGuestArchitecture {
    /// Boots the x86_64 PC machine contract.
    #[default]
    X86_64,
    /// Boots the aarch64 `virt` machine contract.
    Aarch64,
}

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
const WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1: &str = "x86-port-00e7-unclaimed-v1";
const WHITEBOX_SETUP_AARCH64_HINT_INERT_V1: &str = "aarch64-hint-4c-inert-v1";
const FAULT_TARGET_NODE_DOMAIN: &[u8] = b"crucible.qemu.fault-target-node.v1\0";

/// Derives the process-bound fault target identity from a canonical node name.
#[must_use]
pub fn qemu_fault_target_hash(node_name: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FAULT_TARGET_NODE_DOMAIN);
    hasher.update(node_name.as_bytes());
    *hasher.finalize().as_bytes()
}
const FIXED_PLUGIN_SIM_FD: i32 = 3;
const FIXED_PLUGIN_SHMEM_FD: i32 = 4;
const FIXED_PLUGIN_WAKE_FD: i32 = 5;
/// Fixed child descriptor number for the host/plugin control socket.
pub const QEMU_PLUGIN_CONTROL_FD: i32 = FIXED_PLUGIN_SIM_FD;
/// Fixed child descriptor number for the inherited shared-memory region.
pub const QEMU_PLUGIN_SHMEM_FD: i32 = FIXED_PLUGIN_SHMEM_FD;
/// Fixed child descriptor number for the inherited wake event descriptor.
pub const QEMU_PLUGIN_WAKE_FD: i32 = FIXED_PLUGIN_WAKE_FD;
/// Default per-run copy-on-write overlay file consumed by QEMU launch commands.
pub const DEFAULT_ROOT_OVERLAY_FILE_NAME: &str = "crucible-root-overlay.qcow2";
/// Default per-run qcow2 container for exact VMState snapshots.
pub const DEFAULT_VMSTATE_FILE_NAME: &str = "crucible-vmstate.qcow2";
/// Node name of the parentless qcow2 VMState container in every launch.
///
/// Hot-fork child-private file plans select the container's writable leaf by
/// this name, so it is part of the QEMU-facing launch contract.
pub const DEFAULT_VMSTATE_NODE_NAME: &str = "vmstate";
const VMSTATE_DRIVE_ID: &str = DEFAULT_VMSTATE_NODE_NAME;
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

/// A validated QEMU launch command prepared for process spawning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchCommand {
    executable: String,
    args: Vec<String>,
    vmstate_size_mib: u64,
    vm_hash_material: String,
    gdbstub: Option<QemuGdbstubChannelConfig>,
    qmp: Option<QemuQmpChannelConfig>,
    plugin_coverage: QemuLaunchPluginSwitch,
    plugin_fault_node_hash: [u8; 32],
    fault_capability_requirement: crate::QemuFaultCapabilityRequirement,
    resource_requirements: QemuLaunchResourceRequirements,
    plugin_setup_plan: crucible_protocol::plugin_setup_plan::PluginSetupPlan,
    plugin_setup_plan_digest: [u8; 32],
}

/// Static host-resource baseline derived from one validated launch command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLaunchResourceRequirements {
    virtual_cpus: u32,
    guest_memory_bytes: u64,
    minimum_writable_bytes: u64,
    root_overlay: bool,
}

impl QemuLaunchResourceRequirements {
    /// Builds the fixed host-resource baseline for one VM shape.
    ///
    /// The writable minimum reserves the guest memory plus the fixed VMState
    /// container headroom every launch profile carries.
    #[must_use]
    pub const fn from_vm_shape(memory_mib: u32, smp_vcpus: u16, root_overlay: bool) -> Self {
        let mebibyte = 1024_u64 * 1024;
        Self {
            virtual_cpus: smp_vcpus as u32,
            guest_memory_bytes: memory_mib as u64 * mebibyte,
            minimum_writable_bytes: (memory_mib as u64 + 512) * mebibyte,
            root_overlay,
        }
    }

    /// Returns the exact fixed virtual-CPU count.
    #[must_use]
    pub const fn virtual_cpus(self) -> u32 {
        self.virtual_cpus
    }

    /// Returns the fixed guest-RAM baseline in bytes.
    #[must_use]
    pub const fn guest_memory_bytes(self) -> u64 {
        self.guest_memory_bytes
    }

    /// Returns the minimum writable bytes needed by the VMState container.
    #[must_use]
    pub const fn minimum_writable_bytes(self) -> u64 {
        self.minimum_writable_bytes
    }

    /// Returns whether the launch also uses a writable root overlay.
    #[must_use]
    pub const fn has_root_overlay(self) -> bool {
        self.root_overlay
    }

    /// Validates this fixed baseline against admitted executor ceilings.
    ///
    /// The resident value is only the guest-RAM baseline; the concrete host
    /// guard must still reserve QEMU/plugin overhead within the admitted
    /// ceiling. Likewise, a root overlay consumes the remaining aggregate
    /// writable quota after the VMState minimum.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchResourceError`] when vCPU, resident-memory, or
    /// writable-byte admission is below the command's fixed baseline.
    pub const fn validate_ceiling(
        self,
        maximum_vcpus: u32,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Result<(), QemuLaunchResourceError> {
        if self.virtual_cpus > maximum_vcpus {
            return Err(QemuLaunchResourceError::VirtualCpus {
                required: self.virtual_cpus,
                admitted: maximum_vcpus,
            });
        }
        if self.guest_memory_bytes > maximum_resident_bytes {
            return Err(QemuLaunchResourceError::ResidentBytes {
                required: self.guest_memory_bytes,
                admitted: maximum_resident_bytes,
            });
        }
        if self.minimum_writable_bytes > maximum_writable_bytes {
            return Err(QemuLaunchResourceError::WritableBytes {
                required: self.minimum_writable_bytes,
                admitted: maximum_writable_bytes,
            });
        }
        Ok(())
    }
}

impl QemuLaunchCommand {
    /// Returns the executable name or path that will be invoked.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    #[cfg(test)]
    pub(crate) fn with_test_executable(mut self, executable: impl Into<String>) -> Self {
        self.executable = executable.into();
        self
    }

    /// Returns the argv tail passed after the executable.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Returns the virtual size required for the exact-VMState qcow2 container.
    #[must_use]
    pub(crate) const fn vmstate_size_mib(&self) -> u64 {
        self.vmstate_size_mib
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

    /// Returns the node identity hash authenticated by the fault bridge.
    #[must_use]
    pub const fn plugin_fault_node_hash(&self) -> [u8; 32] {
        self.plugin_fault_node_hash
    }

    /// Returns the exact fault manifest bound to this launch identity.
    #[must_use]
    pub const fn fault_capability_requirement(&self) -> &crate::QemuFaultCapabilityRequirement {
        &self.fault_capability_requirement
    }

    /// Returns the static resource baseline authenticated by this command.
    #[must_use]
    pub const fn resource_requirements(&self) -> QemuLaunchResourceRequirements {
        self.resource_requirements
    }

    /// Returns the immutable node-local app-random campaign branch plan.
    #[must_use]
    pub const fn app_random_branch_plan(
        &self,
    ) -> &crucible_protocol::app_random_branch_plan::AppRandomBranchPlan {
        self.plugin_setup_plan.app_random_branch_plan()
    }

    /// Returns the complete version-negotiated plugin setup plan.
    #[must_use]
    pub const fn plugin_setup_plan(
        &self,
    ) -> &crucible_protocol::plugin_setup_plan::PluginSetupPlan {
        &self.plugin_setup_plan
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
        let selectable_is_empty = self.plugin_setup_plan.selectable_catalog_plan()
            == &crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::default();
        let mut lines = Vec::with_capacity(self.args.len() + 6);
        lines.push(if selectable_is_empty {
            "crucible.qemu-launch-command.v2".to_owned()
        } else {
            "crucible.qemu-launch-command.v3".to_owned()
        });
        lines.push("command_line_in_hash=executable-and-argv".to_owned());
        lines.push(format!("executable={}", self.executable));
        lines.push(format!(
            "fault_capability_manifest_v1={}",
            lower_hex(self.fault_capability_requirement.digest())
        ));
        lines.push(format!(
            "ready_marker_manifest_v1={}",
            lower_hex(self.fault_capability_requirement.ready_marker_digest())
        ));
        if selectable_is_empty {
            lines.push(format!(
                "app_random_branch_plan_v1={}",
                lower_hex(
                    *blake3::hash(&self.plugin_setup_plan.app_random_branch_plan().encode())
                        .as_bytes(),
                )
            ));
        } else {
            lines.push(format!(
                "plugin_setup_plan_v1={}",
                lower_hex(self.plugin_setup_plan_digest)
            ));
        }
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
    translation_prefetch: Option<QemuTranslationPrefetchExperiment>,
    console_capture: bool,
    fault_capability_requirement: crate::QemuFaultCapabilityRequirement,
    allow_live_gate_manifest_discovery: bool,
    debug_guest_activation_endpoint: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuTranslationPrefetchExperiment {
    enabled: bool,
    report_path: String,
}

impl QemuLaunchCommandBuilder {
    /// Builds a command builder for an exact World-bound fault manifest.
    #[must_use]
    pub fn new(
        profile: DeterministicLaunchProfile,
        vm: QemuVmLaunchConfig,
        executable: impl Into<String>,
        plugin: QemuLaunchPluginConfig,
        fault_capability_requirement: crate::QemuFaultCapabilityRequirement,
    ) -> Self {
        let executable = executable.into();
        Self {
            profile,
            vm,
            executable,
            plugin,
            gdbstub: None,
            qmp: None,
            translation_prefetch: None,
            console_capture: false,
            fault_capability_requirement,
            allow_live_gate_manifest_discovery: false,
            debug_guest_activation_endpoint: false,
        }
    }

    /// Builds an internal loaded-backend gate command that discovers the live manifest.
    #[must_use]
    pub(crate) fn new_for_live_gate(
        profile: DeterministicLaunchProfile,
        vm: QemuVmLaunchConfig,
        executable: impl Into<String>,
        plugin: QemuLaunchPluginConfig,
        architecture: LivePluginGuestArchitecture,
    ) -> Self {
        let node_name = vm.node_id.as_str();
        let requirement = crate::QemuFaultCapabilityRequirement::live_gate_v1(
            architecture,
            profile.cpu_model.clone(),
            node_name,
            vm.crucible_accelerator.is_some(),
        );
        let mut builder = Self::new(profile, vm, executable, plugin, requirement);
        builder.allow_live_gate_manifest_discovery = true;
        builder
    }

    /// Builds an internal gate command bound to previously observed exact manifests.
    pub(crate) fn new_for_exact_live_gate(
        profile: DeterministicLaunchProfile,
        vm: QemuVmLaunchConfig,
        executable: impl Into<String>,
        plugin: QemuLaunchPluginConfig,
        requirement: crate::QemuFaultCapabilityRequirement,
    ) -> Result<Self, QemuLaunchCommandError> {
        if !requirement.is_exact_live_gate_bound() {
            return Err(QemuLaunchCommandError::InvalidFaultCapabilityRequirement);
        }
        let mut builder = Self::new(profile, vm, executable, plugin, requirement);
        builder.allow_live_gate_manifest_discovery = true;
        Ok(builder)
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

    /// Returns a builder that captures guest serial output in the node run directory.
    ///
    /// The character device is an output sink only from Crucible's perspective:
    /// no host-to-guest write operation is exposed by the runtime.
    #[must_use]
    pub const fn with_console_capture(mut self) -> Self {
        self.console_capture = true;
        self
    }

    /// Returns a builder with the inert debugger activation endpoint.
    ///
    /// No host connects or sends the fixed token until a non-canonical debugger
    /// fork commits, so canonical execution cannot activate the guest agent.
    #[must_use]
    pub const fn with_debug_guest_activation_endpoint(mut self) -> Self {
        self.debug_guest_activation_endpoint = true;
        self
    }

    /// Returns a builder with the gate-only translation-prefetch experiment.
    ///
    /// This host-mechanism switch is intentionally absent from scenario hash
    /// material. It exists only to run the same content-addressed scenario with
    /// helper translation off and on for the PERF-32 neutrality proof.
    #[must_use]
    pub fn with_translation_prefetch_experiment(
        mut self,
        enabled: bool,
        report_path: impl Into<String>,
    ) -> Self {
        self.translation_prefetch = Some(QemuTranslationPrefetchExperiment {
            enabled,
            report_path: report_path.into(),
        });
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
        let fault_capability_requirement = self.fault_capability_requirement;
        let required_target = fault_capability_requirement
            .target_manifest()
            .ok_or(QemuLaunchCommandError::InvalidFaultCapabilityRequirement)?;
        if !self.allow_live_gate_manifest_discovery
            && (!fault_capability_requirement.is_world_bound()
                || required_target.exact_register_manifest().is_none())
        {
            return Err(QemuLaunchCommandError::UnboundFaultCapabilityRequirement);
        }
        if required_target.node_hash() != crate::qemu_fault_target_hash(&self.vm.node_id)
            || required_target.node_hash() != self.plugin.fault_node_hash()
        {
            return Err(QemuLaunchCommandError::FaultCapabilityNodeMismatch);
        }
        if self.vm.crucible_accelerator.is_some()
            != required_target.exact_accelerator_manifest().is_some()
        {
            return Err(QemuLaunchCommandError::AcceleratorCapabilityMismatch);
        }
        let executable_architecture = if self.executable.ends_with("qemu-system-x86_64") {
            crucible_shmem::FaultCapabilityScope::X86_64
        } else if self.executable.ends_with("qemu-system-aarch64") {
            crucible_shmem::FaultCapabilityScope::Aarch64
        } else {
            return Err(
                QemuLaunchCommandError::UnsupportedFaultCapabilityArchitecture {
                    executable: self.executable.clone(),
                },
            );
        };
        if required_target.architecture() != executable_architecture {
            return Err(QemuLaunchCommandError::FaultCapabilityArchitectureMismatch);
        }
        let configured_cpu = self
            .profile
            .cpu_model
            .split(',')
            .next()
            .unwrap_or(&self.profile.cpu_model);
        let expected_suffix = match required_target.architecture() {
            crucible_shmem::FaultCapabilityScope::X86_64 => "-x86_64-cpu",
            crucible_shmem::FaultCapabilityScope::Aarch64 => "-arm-cpu",
            _ => return Err(QemuLaunchCommandError::InvalidFaultCapabilityRequirement),
        };
        let realized_cpu = if configured_cpu.ends_with(expected_suffix) {
            configured_cpu.to_owned()
        } else {
            format!("{configured_cpu}{expected_suffix}")
        };
        if required_target.realized_cpu_type() != realized_cpu {
            return Err(QemuLaunchCommandError::FaultCapabilityCpuModelMismatch);
        }
        if let Some(gdbstub) = &self.gdbstub {
            gdbstub.validate()?;
        }
        if let Some(qmp) = &self.qmp {
            qmp.validate()?;
        }
        if let Some(experiment) = &self.translation_prefetch
            && (!experiment.report_path.starts_with('/') || experiment.report_path.contains(','))
        {
            return Err(QemuLaunchCommandError::InvalidTranslationPrefetchReportPath);
        }

        let vmstate_size_mib = u64::from(self.profile.memory_mib) + 512;
        let resource_requirements = QemuLaunchResourceRequirements::from_vm_shape(
            self.profile.memory_mib,
            self.profile.smp_vcpus,
            self.vm.root_image().is_some(),
        );
        let mut vm_hash_material = self.vm.launch_hash_material();
        if self.debug_guest_activation_endpoint {
            vm_hash_material.push_str("\ndebug_guest_activation_endpoint=fixed-inert-v1");
        }
        let mut args = self.profile.canonical_qemu_args();
        if self.vm.kernel().is_none() {
            remove_option_with_value(&mut args, "-append")?;
        }
        if self.console_capture {
            replace_option_value(
                &mut args,
                "-serial",
                &format!("chardev:{QEMU_CONSOLE_CHARDEV_ID}"),
            )?;
            args.extend([
                "-chardev".to_owned(),
                format!(
                    "socket,id={QEMU_CONSOLE_CHARDEV_ID},path={QEMU_CONSOLE_SOCKET_FILE_NAME},server=on,wait=off"
                ),
            ]);
        }
        if self.debug_guest_activation_endpoint {
            args.extend([
                "-chardev".to_owned(),
                format!(
                    "socket,id={QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID},path={QEMU_DEBUG_GUEST_ACTIVATION_SOCKET_FILE_NAME}"
                ),
                "-device".to_owned(),
                format!("virtio-serial-pci,id={QEMU_DEBUG_GUEST_VIRTIO_SERIAL_ID},bus=pcie.0"),
                "-device".to_owned(),
                format!(
                    "virtserialport,bus={QEMU_DEBUG_GUEST_VIRTIO_SERIAL_ID}.0,chardev={QEMU_DEBUG_GUEST_ACTIVATION_CHARDEV_ID},name={QEMU_DEBUG_GUEST_ACTIVATION_PORT_NAME}"
                ),
            ]);
        }
        if let Some(experiment) = &self.translation_prefetch {
            let accelerator = args
                .windows(2)
                .position(|window| window[0] == "-accel")
                .map(|index| index + 1)
                .ok_or(QemuLaunchCommandError::InvalidLaunchText {
                    field: "translation_prefetch_accelerator",
                })?;
            args[accelerator] = format!(
                "{DEFAULT_ACCEL},crucible-translation-prefetch={},crucible-translation-prefetch-report={}",
                if experiment.enabled { "on" } else { "off" },
                experiment.report_path
            );
        }
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

        let plugin_setup_plan = self.plugin.plugin_setup_plan();
        let plugin_setup_plan_bytes = plugin_setup_plan
            .encode()
            .map_err(|_source| QemuLaunchCommandError::InvalidPluginSetupPlan)?;
        let plugin_setup_plan_digest = *blake3::hash(&plugin_setup_plan_bytes).as_bytes();
        Ok(QemuLaunchCommand {
            executable: self.executable,
            args,
            vmstate_size_mib,
            vm_hash_material,
            gdbstub: self.gdbstub,
            qmp: self.qmp,
            plugin_coverage: self.plugin.coverage(),
            plugin_fault_node_hash: self.plugin.fault_node_hash(),
            fault_capability_requirement,
            resource_requirements,
            plugin_setup_plan,
            plugin_setup_plan_digest,
        })
    }
}

fn lower_hex(bytes: [u8; 32]) -> String {
    bytes
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn replace_option_value(
    args: &mut [String],
    option: &'static str,
    replacement: &str,
) -> Result<(), QemuLaunchCommandError> {
    let Some(index) = args.iter().position(|argument| argument == option) else {
        return Err(QemuLaunchCommandError::InvalidLaunchText { field: option });
    };
    let Some(value) = args.get_mut(index.saturating_add(1)) else {
        return Err(QemuLaunchCommandError::InvalidLaunchText { field: option });
    };
    *value = replacement.to_owned();
    Ok(())
}

fn remove_option_with_value(
    args: &mut Vec<String>,
    option: &'static str,
) -> Result<(), QemuLaunchCommandError> {
    let Some(index) = args.iter().position(|argument| argument == option) else {
        return Err(QemuLaunchCommandError::InvalidLaunchText { field: option });
    };
    if index.saturating_add(1) >= args.len() {
        return Err(QemuLaunchCommandError::InvalidLaunchText { field: option });
    }
    args.drain(index..=index + 1);
    Ok(())
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

/// On-disk format of an immutable root-image backing artifact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum QemuRootImageFormat {
    /// The backing artifact is a QCOW2 image.
    #[default]
    Qcow2,
    /// The backing artifact is a raw disk or filesystem image.
    Raw,
}

impl QemuRootImageFormat {
    const fn qemu_driver(self) -> &'static str {
        match self {
            Self::Qcow2 => "qcow2",
            Self::Raw => "raw",
        }
    }
}

/// VM launch inputs derived from one static `World` VM node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuVmLaunchConfig {
    node_id: String,
    kernel: Option<QemuLaunchArtifact>,
    root_image: Option<QemuLaunchArtifact>,
    firmware: Option<QemuLaunchArtifact>,
    initrd: Option<QemuLaunchArtifact>,
    root_image_format: QemuRootImageFormat,
    root_overlay_file_name: String,
    crucible_shmem_block: Option<CrucibleShmemBlockDevice>,
    crucible_shmem_9p: Option<CrucibleShmem9pDevice>,
    crucible_shmem_network: Option<CrucibleShmemNetworkDevice>,
    crucible_accelerator: Option<CrucibleAcceleratorDevice>,
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
            kernel: Some(kernel),
            root_image: Some(root_image),
            firmware: None,
            initrd: None,
            root_image_format: QemuRootImageFormat::Qcow2,
            root_overlay_file_name: DEFAULT_ROOT_OVERLAY_FILE_NAME.to_owned(),
            crucible_shmem_block: None,
            crucible_shmem_9p: None,
            crucible_shmem_network: None,
            crucible_accelerator: None,
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
            kernel: Some(kernel),
            root_image: None,
            firmware: Some(firmware),
            initrd: None,
            root_image_format: QemuRootImageFormat::Qcow2,
            root_overlay_file_name: DEFAULT_ROOT_OVERLAY_FILE_NAME.to_owned(),
            crucible_shmem_block: None,
            crucible_shmem_9p: None,
            crucible_shmem_network: None,
            crucible_accelerator: None,
        }
    }

    /// Builds a firmware-only VM launch config with no direct kernel payload.
    ///
    /// Firmware selects and boots attached devices using their ordinary QEMU
    /// front-ends. This is useful for boot-path validation where `-kernel` would
    /// bypass firmware disk discovery.
    #[must_use]
    pub fn new_firmware_boot(node_id: impl Into<String>, firmware: QemuLaunchArtifact) -> Self {
        Self {
            node_id: node_id.into(),
            kernel: None,
            root_image: None,
            firmware: Some(firmware),
            initrd: None,
            root_image_format: QemuRootImageFormat::Qcow2,
            root_overlay_file_name: DEFAULT_ROOT_OVERLAY_FILE_NAME.to_owned(),
            crucible_shmem_block: None,
            crucible_shmem_9p: None,
            crucible_shmem_network: None,
            crucible_accelerator: None,
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

    /// Returns a config with the declared immutable root-image format.
    #[must_use]
    pub const fn with_root_image_format(mut self, format: QemuRootImageFormat) -> Self {
        self.root_image_format = format;
        self
    }

    /// Returns a config that attaches a crucible-shmem virtio-blk device.
    ///
    /// The device is opened through the typed `-blockdev
    /// driver=crucible-shmem` interface and backed by the host I/O sub-node over
    /// the `SLOT_BLK_IO` shared-memory rings. A config without one emits
    /// byte-identical argv.
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

    /// Returns a config with a deterministic accelerator co-simulation device.
    #[must_use]
    pub fn with_crucible_accelerator(mut self, device: CrucibleAcceleratorDevice) -> Self {
        self.crucible_accelerator = Some(device);
        self
    }

    /// Returns the attached deterministic accelerator, if present.
    #[must_use]
    pub const fn crucible_accelerator(&self) -> Option<&CrucibleAcceleratorDevice> {
        self.crucible_accelerator.as_ref()
    }

    /// Returns the static scenario node identifier.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Returns the directly loaded kernel artifact, if one is configured.
    #[must_use]
    pub const fn kernel(&self) -> Option<&QemuLaunchArtifact> {
        self.kernel.as_ref()
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
        ];
        match &self.kernel {
            Some(kernel) => {
                lines.push(format!(
                    "kernel_hash={}",
                    content_hash_hex(kernel.content_hash)
                ));
                lines.push(format!("kernel_path={}", kernel.path));
            }
            None => lines.push("kernel=firmware-boot".to_owned()),
        }
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
                if self.root_image_format == QemuRootImageFormat::Raw {
                    lines.push("root_image_format=raw".to_owned());
                }
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
        if let Some(device) = &self.crucible_accelerator {
            device.append_hash_material(&mut lines);
        }
        lines.join("\n")
    }

    fn qemu_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        args.extend([
            "-blockdev".to_owned(),
            format!(
                "driver=qcow2,node-name={VMSTATE_DRIVE_ID},file.driver=file,file.filename={DEFAULT_VMSTATE_FILE_NAME}"
            ),
        ]);
        if let Some(firmware) = &self.firmware {
            args.extend(["-bios".to_owned(), firmware.path.clone()]);
        }
        if let Some(kernel) = &self.kernel {
            args.extend(["-kernel".to_owned(), kernel.path.clone()]);
        }
        if let Some(root_image) = &self.root_image {
            args.extend([
                "-drive".to_owned(),
                format!(
                    "id={ROOT_DRIVE_ID},file={},backing.driver={},backing.file.driver=file,backing.file.filename={},if=none,format=qcow2,cache=none,aio=threads,discard=unmap",
                    self.root_overlay_file_name,
                    self.root_image_format.qemu_driver(),
                    root_image.path
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
        if let Some(device) = &self.crucible_accelerator {
            device.append_qemu_args(&mut args);
        }
        args
    }

    fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_launch_text("node_id", &self.node_id)?;
        if let Some(kernel) = &self.kernel {
            kernel.validate("kernel_path")?;
        }
        if let Some(firmware) = &self.firmware {
            firmware.validate("firmware_path")?;
        }
        if let Some(root_image) = &self.root_image {
            root_image.validate("root_image_path")?;
            validate_overlay_file_name(&self.root_overlay_file_name)?;
        }
        if let Some(initrd) = &self.initrd {
            if self.kernel.is_none() {
                return Err(QemuLaunchCommandError::InitrdWithoutKernel);
            }
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
        if let Some(device) = &self.crucible_accelerator {
            device.validate()?;
        }
        Ok(())
    }
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

    /// Returns the canonical CPU-model identity pinned by this profile.
    #[must_use]
    pub(crate) fn cpu_model(&self) -> &str {
        &self.cpu_model
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
            format!("base={DEFAULT_RTC_EPOCH_UTC},clock=vm"),
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
    /// Returns [`QemuLaunchCommandError`] when the World manifest is invalid,
    /// any node, architecture, or CPU identity differs, command construction
    /// fails, or final pre-spawn validation rejects the command.
    pub fn qemu_launch_command(
        &self,
        vm: QemuVmLaunchConfig,
        executable: impl Into<String>,
        plugin: QemuLaunchPluginConfig,
        node: &crucible::model::WorldNodeFaultCapabilities,
    ) -> Result<QemuLaunchCommand, QemuLaunchCommandError> {
        let requirement = crate::QemuFaultCapabilityRequirement::current_v1_for_node(node)
            .map_err(|_source| QemuLaunchCommandError::InvalidFaultCapabilityRequirement)?;
        QemuLaunchCommandBuilder::new(self.clone(), vm, executable, plugin, requirement).build()
    }

    /// Builds a loaded-backend gate command with live manifest discovery.
    ///
    /// This crate-private path exists only for gates whose purpose is to query
    /// the real QEMU backend. Production launches use [`Self::qemu_launch_command`].
    pub(crate) fn qemu_launch_command_for_live_gate(
        &self,
        vm: QemuVmLaunchConfig,
        executable: impl Into<String>,
        plugin: QemuLaunchPluginConfig,
        architecture: LivePluginGuestArchitecture,
    ) -> Result<QemuLaunchCommand, QemuLaunchCommandError> {
        QemuLaunchCommandBuilder::new_for_live_gate(
            self.clone(),
            vm,
            executable,
            plugin,
            architecture,
        )
        .build()
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
            format!("rtc_epoch_utc={DEFAULT_RTC_EPOCH_UTC}"),
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

    /// Derives the scheduler's RUN-subdivision policy from this exact launch profile.
    ///
    /// This keeps the scheduler model and patched QEMU on the same vCPU count
    /// and retired-instruction switch quantum instead of duplicating launch
    /// defaults at the call site.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if the validated launch topology cannot be
    /// represented as a scheduler subdivision policy.
    pub fn scheduler_run_subdivision_policy(
        &self,
        node: SchedulerNodeId,
    ) -> Result<SchedulerRunSubdivisionPolicy, SchedulerError> {
        SchedulerRunSubdivisionPolicy::new(node, u32::from(self.smp_vcpus), self.rr_switch_quantum)
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

// The launch-profile mode enums and their `Display` renderings live in the
// `modes` submodule and are re-exported above, next to the other launch types.
