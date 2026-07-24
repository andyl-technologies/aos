//! Validation errors and parsers for deterministic QEMU launch profiles.

use thiserror::Error;

use super::{
    DEFAULT_ACCEL, DiskImageMode, GuestBackingStateMode, GuestCoreContentMode, InputPolicy,
    MAX_ICOUNT_SHIFT, MAX_RR_SWITCH_QUANTUM, MachineResetMode, entropy::GUEST_ENTROPY_RNG_ID,
};

mod values;

use values::{comma_value, unique_comma_value_any, unique_option_value};
pub(super) use values::{option_values, unique_comma_value, validate_fixed_text};

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
    /// The accelerator was not the single-threaded TCG-derived sim accelerator.
    #[error("accelerator must be `sim,thread=single`, got `{accelerator}`")]
    AcceleratorNotSingleThreadSim {
        /// The rejected accelerator string.
        accelerator: String,
    },
    /// The launch requested zero vCPUs.
    #[error("launch profile requires at least one vCPU")]
    SmpVcpuCountZero,
    /// The launch requested adaptive host-speed icount.
    #[error("icount shift must be fixed; `shift=auto` is forbidden")]
    IcountShiftAuto,
    /// The fixed icount shift was too large for checked virtual-time math.
    #[error("icount shift {shift} exceeds maximum {MAX_ICOUNT_SHIFT}")]
    IcountShiftTooLarge {
        /// The rejected shift.
        shift: u8,
    },
    /// The round-robin vCPU switch quantum was zero.
    #[error("RR switch quantum must be a non-zero node-icount value")]
    RrSwitchQuantumZero,
    /// The round-robin vCPU switch quantum exceeded the patched QEMU limit.
    #[error("RR switch quantum {quantum} exceeds maximum {MAX_RR_SWITCH_QUANTUM}")]
    RrSwitchQuantumTooLarge {
        /// Rejected round-robin switch quantum.
        quantum: u64,
    },
    /// A node requested a fixed icount shift different from the scenario shift.
    #[error(
        "node `{node_id}` icount shift {node_shift} differs from scenario shift {scenario_shift}"
    )]
    IcountShiftMismatch {
        /// The node whose launch declaration mismatched the scenario.
        node_id: String,
        /// The scenario-wide fixed shift.
        scenario_shift: u8,
        /// The node-local fixed shift.
        node_shift: u8,
    },
    /// A node had more than one icount shift declaration in scenario content.
    #[error("node `{node_id}` has duplicate icount shift declarations")]
    DuplicateNodeIcountShift {
        /// The node declared more than once.
        node_id: String,
    },
    /// A node had more than one clock-skew declaration in scenario content.
    #[error("node `{node_id}` has duplicate clock skew declarations")]
    DuplicateNodeClockSkew {
        /// The node declared more than once.
        node_id: String,
    },
    /// A node clock-skew declaration used an invalid drift rate.
    #[error("node `{node_id}` clock drift rate {numerator}/{denominator} is invalid")]
    InvalidNodeClockDriftRate {
        /// The node whose clock skew was invalid.
        node_id: String,
        /// The invalid drift-rate numerator.
        numerator: u64,
        /// The invalid drift-rate denominator.
        denominator: u64,
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
    #[error("disk image mode must be copy-on-write or diskless, got `{mode}`")]
    DiskImageMutatesBacking {
        /// The rejected disk mode.
        mode: DiskImageMode,
    },
    /// Genesis backing state would not be byte-identical across runs.
    #[error("guest backing state must be byte-identical or absent, got `{mode}`")]
    GuestBackingStateNotByteIdentical {
        /// The rejected guest backing-state mode.
        mode: GuestBackingStateMode,
    },
    /// Disk and backing-state policies described different storage surfaces.
    #[error("disk image mode `{disk}` is incompatible with backing-state mode `{backing}`")]
    StorageModeMismatch {
        /// Disk device/write policy.
        disk: DiskImageMode,
        /// Backing-state identity policy.
        backing: GuestBackingStateMode,
    },
    /// Core operation would require Crucible content inside the guest.
    #[error("core operation must remain host-side only, got `{mode}`")]
    GuestCoreContentRequired {
        /// The rejected guest core-content mode.
        mode: GuestCoreContentMode,
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

/// A validated pre-spawn QEMU launch-argument summary.
///
/// This is the last validation layer before process spawn: it parses the
/// concrete argv that will be handed to QEMU and rejects host-timing,
/// host-entropy, or non-TCG launch modes even if they bypassed the typed launch
/// builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuPreSpawnLaunchValidation {
    accelerator: String,
    icount_shift: u8,
    rr_switch_quantum: u64,
    smp_vcpus: u16,
    cpu_model: String,
}

impl QemuPreSpawnLaunchValidation {
    /// Returns the accepted accelerator string.
    #[must_use]
    pub fn accelerator(&self) -> &str {
        &self.accelerator
    }

    /// Returns the accepted fixed icount shift.
    #[must_use]
    pub const fn icount_shift(&self) -> u8 {
        self.icount_shift
    }

    /// Returns the accepted pinned RR switch quantum.
    #[must_use]
    pub const fn rr_switch_quantum(&self) -> u64 {
        self.rr_switch_quantum
    }

    /// Returns the accepted vCPU count.
    #[must_use]
    pub const fn smp_vcpus(&self) -> u16 {
        self.smp_vcpus
    }

    /// Returns the accepted fixed CPU model.
    #[must_use]
    pub fn cpu_model(&self) -> &str {
        &self.cpu_model
    }
}

/// A pre-spawn QEMU launch-argument validation error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum QemuPreSpawnLaunchValidationError {
    /// A required QEMU option was absent.
    #[error("required QEMU option `{option}` is missing")]
    MissingOption {
        /// Missing option name.
        option: &'static str,
    },
    /// A QEMU option that must be unique appeared more than once.
    #[error("QEMU option `{option}` must be unique")]
    DuplicateOption {
        /// Duplicated option name.
        option: &'static str,
    },
    /// A QEMU option that requires a value did not have one.
    #[error("QEMU option `{option}` is missing its value")]
    MissingOptionValue {
        /// Option missing a value.
        option: &'static str,
    },
    /// KVM or another hardware-acceleration shortcut was selected.
    #[error("QEMU launch must not enable KVM or hardware acceleration via `{argument}`")]
    KvmOrHardwareAcceleration {
        /// Rejected argument.
        argument: String,
    },
    /// The selected accelerator was not the TCG-derived sim accelerator.
    #[error("QEMU Crucible launch accelerator must be `sim`, got `{accelerator}`")]
    NonSimAccelerator {
        /// Rejected accelerator string.
        accelerator: String,
    },
    /// Multi-threaded TCG was selected.
    #[error("QEMU launch must reject MTTCG `thread=multi`: `{accelerator}`")]
    MultiThreadTcg {
        /// Rejected accelerator string.
        accelerator: String,
    },
    /// Single-threaded sim TCG was not explicitly selected.
    #[error("QEMU sim launch must pin `thread=single`, got `{accelerator}`")]
    SingleThreadSimNotPinned {
        /// Rejected accelerator string.
        accelerator: String,
    },
    /// The icount argument did not include a fixed shift.
    #[error("QEMU `-icount` must include fixed `shift=N`")]
    IcountShiftMissing,
    /// The icount argument selected adaptive host-speed shift mode.
    #[error("QEMU `-icount shift=auto` is forbidden")]
    IcountShiftAuto,
    /// The icount shift could not be parsed or was out of range.
    #[error("QEMU `-icount` shift `{value}` is invalid")]
    IcountShiftInvalid {
        /// Invalid shift value.
        value: String,
    },
    /// The icount argument did not pin a required key.
    #[error("QEMU `-icount` must include `{key}={expected}`")]
    IcountOptionMissing {
        /// Missing key.
        key: &'static str,
        /// Expected value.
        expected: &'static str,
    },
    /// The icount argument used a forbidden key value.
    #[error("QEMU `-icount` must use `{key}={expected}`, got `{value}`")]
    IcountOptionInvalid {
        /// Invalid key.
        key: &'static str,
        /// Expected value.
        expected: &'static str,
        /// Rejected value.
        value: String,
    },
    /// A comma-delimited QEMU option repeated a deterministic sub-option key.
    #[error("QEMU `{option}` must specify `{key}` at most once")]
    DuplicateSubOption {
        /// The parent QEMU option.
        option: &'static str,
        /// The duplicated sub-option key.
        key: &'static str,
    },
    /// The RR switch quantum was not pinned.
    #[error("QEMU `-icount` must pin `rr_switch_quantum` in node icount")]
    RrSwitchQuantumUnpinned,
    /// The RR switch quantum could not be parsed.
    #[error("QEMU `rr_switch_quantum` value `{value}` is invalid")]
    RrSwitchQuantumInvalid {
        /// Invalid quantum value.
        value: String,
    },
    /// The RR switch quantum was zero.
    #[error("QEMU `rr_switch_quantum` must be non-zero")]
    RrSwitchQuantumZero,
    /// The RR switch quantum exceeded the patched QEMU limit.
    #[error("QEMU `rr_switch_quantum` {quantum} exceeds maximum {MAX_RR_SWITCH_QUANTUM}")]
    RrSwitchQuantumTooLarge {
        /// Rejected round-robin switch quantum.
        quantum: u64,
    },
    /// The vCPU count could not be parsed.
    #[error("QEMU `-smp` value `{value}` is invalid")]
    SmpInvalid {
        /// Invalid `-smp` value.
        value: String,
    },
    /// The vCPU count was zero.
    #[error("QEMU `-smp` must request at least one vCPU")]
    SmpZero,
    /// The CPU model inherited host CPU features.
    #[error("QEMU launch CPU model must not be `host`")]
    CpuModelUsesHost,
    /// The CPU model enabled hardware entropy instructions.
    #[error("QEMU launch CPU model enables host entropy feature `{feature}`")]
    CpuEntropyFeatureEnabled {
        /// Enabled entropy feature.
        feature: &'static str,
    },
    /// A machine option selected an accelerator other than sim.
    #[error("QEMU Crucible machine option selects a non-sim accelerator: `{machine}`")]
    MachineUsesNonSimAcceleration {
        /// Rejected machine argument.
        machine: String,
    },
    /// A launch flag introduced host timing or host entropy.
    #[error("QEMU launch argument `{argument}` introduces {reason}")]
    HostTimingOrEntropyArgument {
        /// Rejected argument.
        argument: String,
        /// Human-readable rejection reason.
        reason: &'static str,
    },
}

/// Validates a concrete QEMU argv before spawning a child.
///
/// # Errors
///
/// Returns [`QemuPreSpawnLaunchValidationError`] when the argv does not select
/// the TCG-derived `sim` accelerator, selects KVM or MTTCG, omits fixed icount,
/// uses `shift=auto`, leaves the RR switch quantum unpinned, inherits host CPU
/// entropy, or enables a host-timing/host-entropy device.
pub fn validate_pre_spawn_qemu_launch_args(
    args: &[String],
) -> Result<QemuPreSpawnLaunchValidation, QemuPreSpawnLaunchValidationError> {
    super::control_channels::validate_optional_pre_spawn_qmp_control_endpoint(args)?;
    reject_kvm_and_host_sources(args)?;
    let accelerator = unique_option_value(args, "-accel")?.to_owned();
    validate_pre_spawn_accelerator(&accelerator)?;

    for machine in option_values(args, "-machine")? {
        validate_machine_acceleration(machine)?;
    }

    let icount = unique_option_value(args, "-icount")?;
    let icount_shift = validate_pre_spawn_icount_shift(icount)?;
    validate_required_icount_value(icount, "sleep", "off")?;
    validate_required_icount_value(icount, "align", "off")?;
    let rr_switch_quantum = validate_pre_spawn_rr_switch_quantum(icount)?;

    let smp_vcpus = validate_pre_spawn_smp(unique_option_value(args, "-smp")?)?;
    let cpu_model = unique_option_value(args, "-cpu")?.to_owned();
    validate_pre_spawn_cpu(&cpu_model)?;

    Ok(QemuPreSpawnLaunchValidation {
        accelerator,
        icount_shift,
        rr_switch_quantum,
        smp_vcpus,
        cpu_model,
    })
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
        Err(LaunchProfileError::AcceleratorNotSingleThreadSim {
            accelerator: accelerator.to_owned(),
        })
    }
}

fn validate_pre_spawn_accelerator(
    accelerator: &str,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    let lower = accelerator.to_ascii_lowercase();
    let accel = lower.split(',').next().unwrap_or_default().trim();
    if accel == "kvm" || accel == "hvf" || accel == "whpx" {
        return Err(
            QemuPreSpawnLaunchValidationError::KvmOrHardwareAcceleration {
                argument: accelerator.to_owned(),
            },
        );
    }
    if accel != "sim" {
        return Err(QemuPreSpawnLaunchValidationError::NonSimAccelerator {
            accelerator: accelerator.to_owned(),
        });
    }

    match unique_comma_value(&lower, "-accel", "thread")? {
        Some("single") => Ok(()),
        Some("multi") => Err(QemuPreSpawnLaunchValidationError::MultiThreadTcg {
            accelerator: accelerator.to_owned(),
        }),
        Some(_) | None => Err(
            QemuPreSpawnLaunchValidationError::SingleThreadSimNotPinned {
                accelerator: accelerator.to_owned(),
            },
        ),
    }
}

fn validate_machine_acceleration(machine: &str) -> Result<(), QemuPreSpawnLaunchValidationError> {
    let lower = machine.to_ascii_lowercase();
    if let Some(accel) = unique_comma_value(&lower, "-machine", "accel")?
        && accel != "sim"
    {
        return Err(
            QemuPreSpawnLaunchValidationError::MachineUsesNonSimAcceleration {
                machine: machine.to_owned(),
            },
        );
    }
    Ok(())
}

fn validate_pre_spawn_icount_shift(icount: &str) -> Result<u8, QemuPreSpawnLaunchValidationError> {
    let Some(shift) = unique_comma_value(icount, "-icount", "shift")? else {
        return Err(QemuPreSpawnLaunchValidationError::IcountShiftMissing);
    };
    if shift == "auto" {
        return Err(QemuPreSpawnLaunchValidationError::IcountShiftAuto);
    }

    let Ok(shift) = shift.parse::<u8>() else {
        return Err(QemuPreSpawnLaunchValidationError::IcountShiftInvalid {
            value: shift.to_owned(),
        });
    };
    if shift > MAX_ICOUNT_SHIFT {
        return Err(QemuPreSpawnLaunchValidationError::IcountShiftInvalid {
            value: shift.to_string(),
        });
    }
    Ok(shift)
}

fn validate_required_icount_value(
    icount: &str,
    key: &'static str,
    expected: &'static str,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    match unique_comma_value(icount, "-icount", key)? {
        Some(value) if value == expected => Ok(()),
        Some(value) => Err(QemuPreSpawnLaunchValidationError::IcountOptionInvalid {
            key,
            expected,
            value: value.to_owned(),
        }),
        None => Err(QemuPreSpawnLaunchValidationError::IcountOptionMissing { key, expected }),
    }
}

fn validate_pre_spawn_rr_switch_quantum(
    icount: &str,
) -> Result<u64, QemuPreSpawnLaunchValidationError> {
    let Some(value) = unique_comma_value_any(
        icount,
        "-icount",
        &["rr_switch_quantum", "crucible-rr-quantum-icount"],
        "rr_switch_quantum",
    )?
    else {
        return Err(QemuPreSpawnLaunchValidationError::RrSwitchQuantumUnpinned);
    };
    let Ok(quantum) = value.parse::<u64>() else {
        return Err(QemuPreSpawnLaunchValidationError::RrSwitchQuantumInvalid {
            value: value.to_owned(),
        });
    };
    if quantum == 0 {
        return Err(QemuPreSpawnLaunchValidationError::RrSwitchQuantumZero);
    }
    if quantum > MAX_RR_SWITCH_QUANTUM {
        return Err(QemuPreSpawnLaunchValidationError::RrSwitchQuantumTooLarge { quantum });
    }
    Ok(quantum)
}

fn validate_pre_spawn_smp(smp: &str) -> Result<u16, QemuPreSpawnLaunchValidationError> {
    let cpus = unique_comma_value(smp, "-smp", "cpus")?
        .unwrap_or_else(|| smp.split(',').next().unwrap_or_default());
    let Ok(cpus) = cpus.parse::<u16>() else {
        return Err(QemuPreSpawnLaunchValidationError::SmpInvalid {
            value: smp.to_owned(),
        });
    };
    if cpus == 0 {
        return Err(QemuPreSpawnLaunchValidationError::SmpZero);
    }
    Ok(cpus)
}

fn validate_pre_spawn_cpu(cpu_model: &str) -> Result<(), QemuPreSpawnLaunchValidationError> {
    let lower = cpu_model.to_ascii_lowercase();
    let base = lower.split(',').next().unwrap_or_default();
    if base == "host" {
        return Err(QemuPreSpawnLaunchValidationError::CpuModelUsesHost);
    }
    for feature in ["rdrand", "rdseed"] {
        if lower.split(',').any(|part| {
            let part = part.trim();
            part == feature || part == format!("+{feature}") || part == format!("{feature}=on")
        }) {
            return Err(QemuPreSpawnLaunchValidationError::CpuEntropyFeatureEnabled { feature });
        }
    }
    Ok(())
}

fn reject_kvm_and_host_sources(args: &[String]) -> Result<(), QemuPreSpawnLaunchValidationError> {
    for (index, argument) in args.iter().enumerate() {
        let lower = argument.to_ascii_lowercase();
        if lower == "-enable-kvm" || lower == "--enable-kvm" {
            return Err(
                QemuPreSpawnLaunchValidationError::KvmOrHardwareAcceleration {
                    argument: argument.clone(),
                },
            );
        }
        if lower.contains("/dev/random") || lower.contains("/dev/urandom") {
            return Err(
                QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                    argument: argument.clone(),
                    reason: "host entropy",
                },
            );
        }

        let value = args.get(index + 1).map(String::as_str);
        reject_option_host_source(argument, value)?;
    }
    Ok(())
}

fn reject_option_host_source(
    option: &str,
    value: Option<&str>,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    let (option, value, display_argument) =
        if let Some((inline_option, inline_value)) = option.split_once('=') {
            (inline_option, inline_value, option.to_owned())
        } else {
            let value = value.unwrap_or_default();
            (option, value, format!("{option} {value}"))
        };
    let lower_option = option.to_ascii_lowercase();
    let lower_value = value.to_ascii_lowercase();
    match lower_option.as_str() {
        "-net" | "-netdev" | "-nic" => {
            validate_disabled_network_option(&lower_value, display_argument)
        }
        "-chardev" => validate_internal_chardev_option(&lower_value, display_argument),
        "-serial" | "-parallel" | "-monitor" => {
            validate_disabled_character_frontend(&lower_value, display_argument)
        }
        "-usbdevice" => Err(host_source_argument(
            display_argument,
            "host USB or legacy passthrough input",
        )),
        "-rtc" => validate_pre_spawn_rtc(value),
        "-object"
            if lower_value.starts_with("rng-random") || lower_value.starts_with("rng-egd") =>
        {
            Err(
                QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                    argument: display_argument,
                    reason: "host entropy",
                },
            )
        }
        "-device" => validate_device_option(&lower_value, display_argument),
        "-realtime" | "-real-time" => Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: option.to_owned(),
                reason: "host realtime clocking",
            },
        ),
        _ => Ok(()),
    }
}

fn validate_disabled_network_option(
    value: &str,
    display_argument: String,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    if value.trim() == "none" {
        return Ok(());
    }
    if option_model(value) == "hubport" && is_hostless_hubport(value) {
        return Ok(());
    }

    let reason = if option_model(value) == "user" {
        "host-timing user networking"
    } else {
        "host-timed or host-fed networking"
    };
    Err(host_source_argument(display_argument, reason))
}

/// Returns whether a hubport has only its local identity and emulated-hub id.
///
/// A `netdev=<backend>` sub-option would bridge the hub to another QEMU netdev
/// and is therefore deliberately excluded.
fn is_hostless_hubport(value: &str) -> bool {
    let mut saw_id = false;
    let mut saw_hub_id = false;
    for option in value.split(',').skip(1) {
        let Some((key, option_value)) = option.split_once('=') else {
            return false;
        };
        if option_value.is_empty() {
            return false;
        }
        match key {
            "id" if !saw_id => saw_id = true,
            "hubid" if !saw_hub_id && option_value.bytes().all(|byte| byte.is_ascii_digit()) => {
                saw_hub_id = true;
            }
            _ => return false,
        }
    }
    saw_id && saw_hub_id
}

fn validate_internal_chardev_option(
    value: &str,
    display_argument: String,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    match option_model(value) {
        "null" | "ringbuf" => Ok(()),
        _ => Err(host_source_argument(
            display_argument,
            "host-backed character-device input",
        )),
    }
}

fn validate_disabled_character_frontend(
    value: &str,
    display_argument: String,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    if value.trim() == "none" {
        Ok(())
    } else {
        Err(host_source_argument(
            display_argument,
            "host-backed character frontend input",
        ))
    }
}

fn validate_device_option(
    value: &str,
    display_argument: String,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    let model = option_model(value);
    if is_host_passthrough_device(model) {
        return Err(host_source_argument(
            display_argument,
            "host device passthrough",
        ));
    }
    if is_virtio_rng_device(model) && comma_value(value, "rng") != Some(GUEST_ENTROPY_RNG_ID) {
        return Err(host_source_argument(
            display_argument,
            "unseeded guest entropy",
        ));
    }
    Ok(())
}

fn option_model(value: &str) -> &str {
    value.split(',').next().unwrap_or_default().trim()
}

fn is_virtio_rng_device(model: &str) -> bool {
    matches!(model, "virtio-rng" | "virtio-rng-pci" | "virtio-rng-ccw")
}

fn is_host_passthrough_device(model: &str) -> bool {
    matches!(
        model,
        "usb-host"
            | "usb-redir"
            | "vfio-pci"
            | "vfio-pci-nohotplug"
            | "vfio-platform"
            | "vfio-ap"
            | "vfio-ccw"
            | "pci-assign"
            | "kvm-pci-assign"
            | "ivshmem-plain"
            | "ivshmem-doorbell"
            | "vhost-vdpa"
            | "vhost-user-fs-pci"
            | "vhost-user-scsi-pci"
            | "vhost-user-blk-pci"
            | "vhost-user-gpio-pci"
            | "ccid-card-passthru"
            | "ipmi-bmc-extern"
    ) || model.starts_with("vhost-user-net-")
}

fn host_source_argument(
    argument: String,
    reason: &'static str,
) -> QemuPreSpawnLaunchValidationError {
    QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument { argument, reason }
}

fn validate_pre_spawn_rtc(rtc: &str) -> Result<(), QemuPreSpawnLaunchValidationError> {
    if comma_value(rtc, "clock") != Some("vm") {
        return Err(
            QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                argument: format!("-rtc {rtc}"),
                reason: "host RTC clock",
            },
        );
    }
    match comma_value(rtc, "base") {
        Some("utc") | None => {
            return Err(
                QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                    argument: format!("-rtc {rtc}"),
                    reason: "host RTC base",
                },
            );
        }
        Some("localtime") => {
            return Err(
                QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
                    argument: format!("-rtc {rtc}"),
                    reason: "host localtime",
                },
            );
        }
        Some(_) => {}
    }
    Ok(())
}
