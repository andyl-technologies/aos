//! Deterministic QEMU launch profile construction.
//!
//! The launch profile is the Contract-A boundary where host-specific QEMU
//! defaults become explicit, content-addressed inputs. The module does not spawn
//! QEMU; it validates and serializes the deterministic argument subset that
//! later supervision code will pass to the child process.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use thiserror::Error;

const DEFAULT_CPU_MODEL: &str = "qemu64,-rdrand,-rdseed";
const DEFAULT_MACHINE_TYPE: &str = "pc-q35-9.2";
const DEFAULT_MEMORY_MIB: u32 = 512;
const DEFAULT_ACCEL: &str = "tcg,thread=single";
const DEFAULT_RTC_EPOCH_UTC: &str = "2026-01-01T00:00:00";
const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 quiet nokaslr norandmaps random.trust_cpu=off random.trust_bootloader=off";
const DEFAULT_SCENARIO_SEED: u64 = 0x0010_c001;
const DEFAULT_RUN_SEED: u64 = 0x0010_c001;
const GUEST_ENTROPY_FW_CFG_NAME: &str = "opt/crucible/seed";
const GUEST_ENTROPY_SEED_FILE_NAME: &str = "crucible-guest-entropy-seed.bin";
const GUEST_ENTROPY_RNG_ID: &str = "crucible-rng0";
const GUEST_ENTROPY_SEED_BYTES: usize = 32;
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
            IcountShiftSetting::Fixed(shift) if shift <= MAX_ICOUNT_SHIFT => shift,
            IcountShiftSetting::Fixed(shift) => {
                return Err(LaunchProfileError::IcountShiftTooLarge { shift });
            }
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

/// A deterministic seed delivered to the guest through QEMU firmware config.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestEntropySeed {
    bytes: [u8; GUEST_ENTROPY_SEED_BYTES],
}

impl GuestEntropySeed {
    /// Derives guest entropy from a scenario seed.
    #[must_use]
    pub fn from_scenario_seed(scenario_seed: u64) -> Self {
        let mut bytes = [0; GUEST_ENTROPY_SEED_BYTES];
        let mut state = scenario_seed ^ 0x4352_5543_4942_4c45;

        for (index, chunk) in bytes.chunks_exact_mut(8).enumerate() {
            state = state
                .wrapping_add(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(index as u64);
            chunk.copy_from_slice(&splitmix64(state).to_le_bytes());
        }

        Self { bytes }
    }

    /// Returns the seed bytes as delivered to the guest entropy boundary.
    #[must_use]
    pub fn bytes(&self) -> &[u8; GUEST_ENTROPY_SEED_BYTES] {
        &self.bytes
    }

    /// Returns the seed bytes as lowercase hexadecimal text.
    #[must_use]
    pub fn to_lower_hex(&self) -> String {
        let mut hex = String::with_capacity(GUEST_ENTROPY_SEED_BYTES * 2);
        for byte in self.bytes {
            hex.push(nibble_to_hex(byte >> 4));
            hex.push(nibble_to_hex(byte & 0x0f));
        }
        hex
    }
}

/// A deterministic fw_cfg seed file required by a launch profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestEntropySeedFile {
    file_name: &'static str,
    bytes: [u8; GUEST_ENTROPY_SEED_BYTES],
}

impl GuestEntropySeedFile {
    /// Returns the file name referenced by the canonical QEMU `-fw_cfg` argument.
    #[must_use]
    pub fn file_name(&self) -> &'static str {
        self.file_name
    }

    /// Returns the exact bytes that must be written to the fw_cfg seed file.
    #[must_use]
    pub fn bytes(&self) -> &[u8; GUEST_ENTROPY_SEED_BYTES] {
        &self.bytes
    }

    /// Writes the deterministic seed file into a QEMU working directory.
    ///
    /// # Errors
    ///
    /// Returns any filesystem error reported while writing the seed file.
    pub fn write_to_dir(&self, dir: impl AsRef<Path>) -> std::io::Result<PathBuf> {
        let path = dir.as_ref().join(self.file_name);
        fs::write(&path, self.bytes.as_slice())?;
        Ok(path)
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

/// A deterministic launch-profile validation error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LaunchProfileError {
    /// The CPU model was empty.
    #[error("CPU model must be a fixed non-empty QEMU model")]
    EmptyCpuModel,
    /// The CPU model inherited host CPU features.
    #[error("CPU model must be fixed and must not be `host`")]
    CpuModelUsesHost,
    /// The CPU model enabled hardware entropy instructions.
    #[error("CPU model enables host entropy feature `{feature}`")]
    CpuEntropyFeatureEnabled {
        /// The feature that would expose host entropy.
        feature: &'static str,
    },
    /// The accelerator was not single-threaded TCG.
    #[error("accelerator must be `tcg,thread=single`, got `{accelerator}`")]
    AcceleratorNotSingleThreadTcg {
        /// The rejected accelerator string.
        accelerator: String,
    },
    /// The launch requested more than one vCPU before the RR-TCG profile lands.
    #[error("T-DET-1 launch profile requires `-smp 1`, got {requested}")]
    SmpNotSingleVcpu {
        /// The requested vCPU count.
        requested: u16,
    },
    /// The launch requested adaptive host-speed icount.
    #[error("icount shift must be fixed; `shift=auto` is forbidden")]
    IcountShiftAuto,
    /// The fixed icount shift was too large for checked virtual-time math.
    #[error("icount shift {shift} exceeds maximum {MAX_ICOUNT_SHIFT}")]
    IcountShiftTooLarge {
        /// The rejected shift.
        shift: u8,
    },
    /// The fixed RAM size was zero.
    #[error("memory size must be a fixed non-zero number of MiB")]
    MemorySizeZero,
    /// Text that must be content-addressed was empty or ambiguous.
    #[error("{field} must be fixed non-empty text without newlines or NUL bytes")]
    InvalidFixedText {
        /// The invalid field.
        field: &'static str,
    },
    /// The RTC clock mode was not virtual-clock driven.
    #[error("RTC clock must be `vm`, got `{clock}`")]
    RtcClockNotVm {
        /// The rejected RTC clock mode.
        clock: String,
    },
    /// The kernel command line trusts host CPU randomness.
    #[error("kernel command line must not enable `random.trust_cpu`")]
    KernelTrustsHostCpuRandom,
    /// The kernel command line did not explicitly distrust CPU randomness.
    #[error("kernel command line must include `random.trust_cpu=off`")]
    KernelCpuRandomTrustNotDisabled,
    /// The kernel command line specified CPU random trust more than once.
    #[error("kernel command line must specify `random.trust_cpu=off` exactly once")]
    KernelCpuRandomTrustAmbiguous,
    /// The kernel command line trusts bootloader-provided randomness.
    #[error("kernel command line must not enable `random.trust_bootloader`")]
    KernelTrustsBootloaderRandom,
    /// The kernel command line did not explicitly distrust bootloader randomness.
    #[error("kernel command line must include `random.trust_bootloader=off`")]
    KernelBootloaderRandomTrustNotDisabled,
    /// The kernel command line specified bootloader random trust more than once.
    #[error("kernel command line must specify `random.trust_bootloader=off` exactly once")]
    KernelBootloaderRandomTrustAmbiguous,
    /// The kernel command line explicitly enabled kernel address randomization.
    #[error("kernel command line must not include `kaslr`")]
    KernelKaslrExplicitlyEnabled,
    /// The kernel command line did not disable kernel address randomization.
    #[error("kernel command line must include `nokaslr` exactly once")]
    KernelKaslrNotDisabled,
    /// The kernel command line specified the KASLR disable flag ambiguously.
    #[error("kernel command line must include bare `nokaslr` exactly once")]
    KernelKaslrFlagAmbiguous,
    /// The kernel command line did not disable userspace address randomization.
    #[error("kernel command line must include `norandmaps` exactly once")]
    UserspaceAslrNotDisabled,
    /// The kernel command line specified the userspace ASLR disable flag ambiguously.
    #[error("kernel command line must include bare `norandmaps` exactly once")]
    UserspaceAslrFlagAmbiguous,
    /// The deterministic QEMU run seed diverged from the scenario seed.
    #[error("QEMU run seed {run_seed} must equal scenario seed {scenario_seed}")]
    RunSeedDiffersFromScenarioSeed {
        /// The scenario seed used for guest entropy.
        scenario_seed: u64,
        /// The QEMU run seed used for QEMU internal entropy.
        run_seed: u64,
    },
    /// Machine reset state was not deterministic.
    #[error("machine reset must be deterministic, got `{mode}`")]
    MachineResetNotDeterministic {
        /// The rejected reset mode.
        mode: MachineResetMode,
    },
    /// Guest writes could mutate the backing image.
    #[error("disk image mode must be copy-on-write, got `{mode}`")]
    DiskImageMutatesBacking {
        /// The rejected disk mode.
        mode: DiskImageMode,
    },
    /// Host interactive input was enabled.
    #[error("host interactive input must be disabled, got `{policy}`")]
    InteractiveInputEnabled {
        /// The rejected input policy.
        policy: InputPolicy,
    },
    /// Virtual-time conversion overflowed.
    #[error("virtual time overflow for icount {icount} with shift {shift}")]
    VirtualTimeOverflow {
        /// The input instruction count.
        icount: u64,
        /// The fixed shift.
        shift: u8,
    },
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

fn canonical_cpu_model(cpu_model: &str) -> Result<String, LaunchProfileError> {
    validate_fixed_text("cpu_model", cpu_model)?;
    let lower = cpu_model.to_ascii_lowercase();
    let base = lower.split(',').next().unwrap_or_default();
    if base == "host" {
        return Err(LaunchProfileError::CpuModelUsesHost);
    }
    reject_enabled_entropy_feature(&lower, "rdrand")?;
    reject_enabled_entropy_feature(&lower, "rdseed")?;

    let mut canonical = cpu_model.to_owned();
    if !feature_is_disabled(&lower, "rdrand") {
        canonical.push_str(",-rdrand");
    }
    if !feature_is_disabled(&lower, "rdseed") {
        canonical.push_str(",-rdseed");
    }

    Ok(canonical)
}

fn reject_enabled_entropy_feature(
    lower_cpu_model: &str,
    feature: &'static str,
) -> Result<(), LaunchProfileError> {
    let enabled = lower_cpu_model.split(',').any(|part| {
        let part = part.trim();
        part == feature || part == format!("+{feature}") || part == format!("{feature}=on")
    });
    if enabled {
        Err(LaunchProfileError::CpuEntropyFeatureEnabled { feature })
    } else {
        Ok(())
    }
}

fn feature_is_disabled(lower_cpu_model: &str, feature: &str) -> bool {
    lower_cpu_model.split(',').any(|part| {
        let part = part.trim();
        part == format!("-{feature}") || part == format!("{feature}=off")
    })
}

fn validate_accelerator(accelerator: &str) -> Result<(), LaunchProfileError> {
    if accelerator == DEFAULT_ACCEL {
        Ok(())
    } else {
        Err(LaunchProfileError::AcceleratorNotSingleThreadTcg {
            accelerator: accelerator.to_owned(),
        })
    }
}

fn validate_fixed_text(field: &'static str, value: &str) -> Result<(), LaunchProfileError> {
    if value.is_empty() || value.contains('\n') || value.contains('\0') {
        Err(LaunchProfileError::InvalidFixedText { field })
    } else {
        Ok(())
    }
}

fn require_kernel_random_trust_off(
    cmdline: &str,
    key: &'static str,
    missing: LaunchProfileError,
    enabled: LaunchProfileError,
    ambiguous: LaunchProfileError,
) -> Result<(), LaunchProfileError> {
    match kernel_cmdline_value(cmdline, key) {
        KernelCmdlineValue::Single("off") => Ok(()),
        KernelCmdlineValue::Single(_) => Err(enabled),
        KernelCmdlineValue::Duplicate => Err(ambiguous),
        KernelCmdlineValue::Missing => Err(missing),
    }
}

fn require_kernel_bare_flag_once(
    cmdline: &str,
    key: &str,
    missing: LaunchProfileError,
    ambiguous: LaunchProfileError,
) -> Result<(), LaunchProfileError> {
    match kernel_cmdline_value(cmdline, key) {
        KernelCmdlineValue::Single("") => Ok(()),
        KernelCmdlineValue::Single(_) | KernelCmdlineValue::Duplicate => Err(ambiguous),
        KernelCmdlineValue::Missing => Err(missing),
    }
}

fn reject_kernel_cmdline_key(
    cmdline: &str,
    key: &str,
    error: LaunchProfileError,
) -> Result<(), LaunchProfileError> {
    match kernel_cmdline_value(cmdline, key) {
        KernelCmdlineValue::Missing => Ok(()),
        KernelCmdlineValue::Single(_) | KernelCmdlineValue::Duplicate => Err(error),
    }
}

enum KernelCmdlineValue<'a> {
    Missing,
    Single(&'a str),
    Duplicate,
}

fn kernel_cmdline_value<'a>(cmdline: &'a str, key: &str) -> KernelCmdlineValue<'a> {
    let mut value = None;

    for argument in cmdline.split_ascii_whitespace() {
        let candidate = if argument == key {
            Some("")
        } else {
            argument
                .strip_prefix(key)
                .and_then(|remainder| remainder.strip_prefix('='))
        };

        if let Some(candidate) = candidate {
            if value.is_some() {
                return KernelCmdlineValue::Duplicate;
            }
            value = Some(candidate);
        }
    }

    match value {
        Some(value) => KernelCmdlineValue::Single(value),
        None => KernelCmdlineValue::Missing,
    }
}

fn splitmix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn nibble_to_hex(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        10..=15 => (b'a' + (nibble - 10)) as char,
        _ => unreachable!("nibble is masked to four bits"),
    }
}
