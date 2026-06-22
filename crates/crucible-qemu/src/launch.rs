//! Deterministic QEMU launch profile construction.
//!
//! The launch profile is the Contract-A boundary where host-specific QEMU
//! defaults become explicit, content-addressed inputs. The module does not spawn
//! QEMU; it validates and serializes the deterministic argument subset that
//! later supervision code will pass to the child process.

use std::fmt;

use thiserror::Error;

const DEFAULT_CPU_MODEL: &str = "qemu64,-rdrand,-rdseed";
const DEFAULT_MACHINE_TYPE: &str = "pc-q35-9.2";
const DEFAULT_MEMORY_MIB: u32 = 512;
const DEFAULT_ACCEL: &str = "tcg,thread=single";
const DEFAULT_RTC_EPOCH_UTC: &str = "2026-01-01T00:00:00";
const DEFAULT_KERNEL_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 quiet random.trust_cpu=off";
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
        if self.kernel_cmdline.contains("random.trust_cpu=on") {
            return Err(LaunchProfileError::KernelTrustsHostCpuRandom);
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
        })
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
            format!("kernel_cmdline={}", self.kernel_cmdline),
        ]
        .join("\n")
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
    #[error("kernel command line must not enable `random.trust_cpu=on`")]
    KernelTrustsHostCpuRandom,
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
