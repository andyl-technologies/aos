//! Deterministic QEMU launch profile construction.
//!
//! The launch profile is the Contract-A boundary where host-specific QEMU
//! defaults become explicit, content-addressed inputs. The module does not spawn
//! QEMU; it validates and serializes the deterministic argument subset that
//! later supervision code will pass to the child process.

mod entropy;
mod validation;

use std::fmt;

use entropy::{GUEST_ENTROPY_FW_CFG_NAME, GUEST_ENTROPY_RNG_ID, GUEST_ENTROPY_SEED_FILE_NAME};
pub use entropy::{GuestEntropySeed, GuestEntropySeedFile};
pub use validation::LaunchProfileError;
use validation::{
    canonical_cpu_model, reject_kernel_cmdline_key, require_kernel_bare_flag_once,
    require_kernel_random_trust_off, validate_accelerator, validate_fixed_text,
};

const DEFAULT_CPU_MODEL: &str = "qemu64,-rdrand,-rdseed";
const DEFAULT_MACHINE_TYPE: &str = "pc-q35-9.2";
const DEFAULT_MEMORY_MIB: u32 = 512;
const DEFAULT_ACCEL: &str = "tcg,thread=single";
const DEFAULT_RTC_EPOCH_UTC: &str = "2026-01-01T00:00:00";
const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off";
const DEFAULT_SCENARIO_SEED: u64 = 0x0010_c001;
const DEFAULT_RUN_SEED: u64 = 0x0010_c001;
const MAX_ICOUNT_SHIFT: u8 = 62;

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
            rtc_epoch_utc: DEFAULT_RTC_EPOCH_UTC.to_owned(),
            rtc_clock: "vm".to_owned(),
            kernel_cmdline: DEFAULT_KERNEL_CMDLINE.to_owned(),
            scenario_seed: DEFAULT_SCENARIO_SEED,
            run_seed: DEFAULT_RUN_SEED,
            machine_reset: MachineResetMode::Deterministic,
            disk_image_mode: DiskImageMode::CopyOnWriteOverlay,
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
        if self.smp_vcpus != 1 {
            return Err(LaunchProfileError::SmpNotSingleVcpu {
                requested: self.smp_vcpus,
            });
        }

        let icount_shift = match self.icount_shift {
            IcountShiftSetting::Fixed(shift) => validate_icount_shift(shift)?,
            IcountShiftSetting::Auto => return Err(LaunchProfileError::IcountShiftAuto),
        };

        validate_fixed_text("rtc_epoch_utc", &self.rtc_epoch_utc)?;
        validate_fixed_text("kernel_cmdline", &self.kernel_cmdline)?;
        if self.rtc_clock != "vm" {
            return Err(LaunchProfileError::RtcClockNotVm {
                clock: self.rtc_clock,
            });
        }
        require_kernel_random_trust_off(
            &self.kernel_cmdline,
            "random.trust_cpu",
            LaunchProfileError::KernelCpuRandomTrustNotDisabled,
            LaunchProfileError::KernelTrustsHostCpuRandom,
            LaunchProfileError::KernelCpuRandomTrustAmbiguous,
        )?;
        require_kernel_random_trust_off(
            &self.kernel_cmdline,
            "random.trust_bootloader",
            LaunchProfileError::KernelBootloaderRandomTrustNotDisabled,
            LaunchProfileError::KernelTrustsBootloaderRandom,
            LaunchProfileError::KernelBootloaderRandomTrustAmbiguous,
        )?;
        reject_kernel_cmdline_key(
            &self.kernel_cmdline,
            "kaslr",
            LaunchProfileError::KernelKaslrExplicitlyEnabled,
        )?;
        require_kernel_bare_flag_once(
            &self.kernel_cmdline,
            "nokaslr",
            LaunchProfileError::KernelKaslrNotDisabled,
            LaunchProfileError::KernelKaslrFlagAmbiguous,
        )?;
        require_kernel_bare_flag_once(
            &self.kernel_cmdline,
            "norandmaps",
            LaunchProfileError::UserspaceAslrNotDisabled,
            LaunchProfileError::UserspaceAslrFlagAmbiguous,
        )?;
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
        if self.disk_image_mode != DiskImageMode::CopyOnWriteOverlay {
            return Err(LaunchProfileError::DiskImageMutatesBacking {
                mode: self.disk_image_mode,
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
            icount_shift,
            rtc_epoch_utc: self.rtc_epoch_utc,
            kernel_cmdline: self.kernel_cmdline,
            scenario_seed: self.scenario_seed,
            run_seed: self.run_seed,
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

/// A validated QEMU launch profile for Contract-A hermeticity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterministicLaunchProfile {
    cpu_model: String,
    machine_type: String,
    memory_mib: u32,
    icount_shift: u8,
    rtc_epoch_utc: String,
    kernel_cmdline: String,
    scenario_seed: u64,
    run_seed: u64,
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
            DEFAULT_ACCEL.to_owned(),
            "-cpu".to_owned(),
            self.cpu_model.clone(),
            "-smp".to_owned(),
            "1".to_owned(),
            "-icount".to_owned(),
            format!("shift={},sleep=off,align=off", self.icount_shift),
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

    /// Returns canonical material that must be included in the scenario hash.
    #[must_use]
    pub fn scenario_hash_material(&self) -> String {
        [
            "crucible.launch.v1".to_owned(),
            format!("cpu_model={}", self.cpu_model),
            format!("machine_type={}", self.machine_type),
            format!("memory_mib={}", self.memory_mib),
            "smp_vcpus=1".to_owned(),
            format!("accelerator={DEFAULT_ACCEL}"),
            format!("icount_shift={}", self.icount_shift),
            "virtual_time_ns=icount<<shift".to_owned(),
            format!("rtc_epoch_utc={}", self.rtc_epoch_utc),
            "rtc_clock=vm".to_owned(),
            "machine_reset=deterministic-zeroed-ram-fixed-devices".to_owned(),
            "ram_reset=zeroed-fresh-anonymous-memory".to_owned(),
            "disk_image_mode=copy-on-write-overlay".to_owned(),
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
            format!("kernel_cmdline={}", self.kernel_cmdline),
        ]
        .join("\n")
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

    /// Returns the fixed `-icount shift=N` value pinned by this launch profile.
    #[must_use]
    pub fn icount_shift(&self) -> u8 {
        self.icount_shift
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

fn canonical_node_icount_shift_lines(
    scenario_shift: u8,
    node_shifts: &[NodeIcountShift],
) -> Result<Vec<String>, LaunchProfileError> {
    validate_icount_shift(scenario_shift)?;

    let mut ordered = Vec::with_capacity(node_shifts.len());
    for node_shift in node_shifts {
        validate_fixed_text("node_id", &node_shift.node_id)?;
        validate_icount_shift(node_shift.shift)?;
        if node_shift.shift != scenario_shift {
            return Err(LaunchProfileError::IcountShiftMismatch {
                node_id: node_shift.node_id.clone(),
                scenario_shift,
                node_shift: node_shift.shift,
            });
        }
        ordered.push((node_shift.node_id.clone(), node_shift.shift));
    }

    ordered.sort_by(|left, right| left.0.cmp(&right.0));
    for adjacent in ordered.windows(2) {
        if adjacent[0].0 == adjacent[1].0 {
            return Err(LaunchProfileError::DuplicateNodeIcountShift {
                node_id: adjacent[0].0.clone(),
            });
        }
    }

    Ok(ordered
        .into_iter()
        .map(|(node_id, shift)| format!("node_icount_shift[{node_id}]={shift}"))
        .collect())
}

fn validate_icount_shift(shift: u8) -> Result<u8, LaunchProfileError> {
    if shift <= MAX_ICOUNT_SHIFT {
        Ok(shift)
    } else {
        Err(LaunchProfileError::IcountShiftTooLarge { shift })
    }
}

/// The requested icount shift setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IcountShiftSetting {
    /// A fixed integer shift used in `ns = icount << shift`.
    Fixed(u8),
    /// QEMU's host-speed-adaptive icount mode.
    Auto,
}

/// The reset discipline for RAM and emulated device state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachineResetMode {
    /// RAM and device reset values are fixed before the genesis run starts.
    Deterministic,
    /// Reset state is left to backend or host defaults.
    HostProvided,
}

/// The backing-image write policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskImageMode {
    /// Guest writes land in a copy-on-write overlay.
    CopyOnWriteOverlay,
    /// Guest writes may mutate the backing image.
    WritableBacking,
}

/// The host interactive input policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputPolicy {
    /// No keyboard, mouse, monitor, or serial input is accepted from the host.
    NoInteractiveInput,
    /// Host interactive input devices may be enabled.
    HostInteractive,
}

impl fmt::Display for MachineResetMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deterministic => f.write_str("deterministic"),
            Self::HostProvided => f.write_str("host-provided"),
        }
    }
}

impl fmt::Display for DiskImageMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CopyOnWriteOverlay => f.write_str("copy-on-write-overlay"),
            Self::WritableBacking => f.write_str("writable-backing"),
        }
    }
}

impl fmt::Display for InputPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInteractiveInput => f.write_str("no-interactive-input"),
            Self::HostInteractive => f.write_str("host-interactive"),
        }
    }
}
