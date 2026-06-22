//! Validation errors and parsers for deterministic QEMU launch profiles.

use thiserror::Error;

use super::{DEFAULT_ACCEL, DiskImageMode, InputPolicy, MAX_ICOUNT_SHIFT, MachineResetMode};

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

pub(super) fn canonical_cpu_model(cpu_model: &str) -> Result<String, LaunchProfileError> {
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

pub(super) fn validate_accelerator(accelerator: &str) -> Result<(), LaunchProfileError> {
    if accelerator == DEFAULT_ACCEL {
        Ok(())
    } else {
        Err(LaunchProfileError::AcceleratorNotSingleThreadTcg {
            accelerator: accelerator.to_owned(),
        })
    }
}

pub(super) fn validate_fixed_text(
    field: &'static str,
    value: &str,
) -> Result<(), LaunchProfileError> {
    if value.is_empty() || value.contains('\n') || value.contains('\0') {
        Err(LaunchProfileError::InvalidFixedText { field })
    } else {
        Ok(())
    }
}

pub(super) fn require_kernel_random_trust_off(
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

pub(super) fn require_kernel_bare_flag_once(
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

pub(super) fn reject_kernel_cmdline_key(
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
