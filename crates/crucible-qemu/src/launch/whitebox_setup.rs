//! Live QEMU doorbell collision discovery and inert-instruction attestation.
//!
//! White-box setup launches the exact configured machine in a stopped,
//! plugin-free probe process and asks QEMU's monitor for the flattened I/O
//! address-space map. The reserved port may be attested only when QEMU reports
//! that the generic `io` fallback region, rather than a device region, owns it.

use std::{
    io::Write as _,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use crucible_protocol::{
    WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION, WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
};
use thiserror::Error;

use super::{
    DEFAULT_VMSTATE_FILE_NAME, QemuLaunchCommand, ROOT_DRIVE_ID, VMSTATE_DRIVE_ID,
    validate_overlay_file_name,
};

const UNASSIGNED_X86_IO_REGION: &str = "io";
const X86_WHITEBOX_MONITOR_QUERY: &[u8] = b"info mtree -f\nquit\n";
const MAXIMUM_X86_WHITEBOX_PROBE_OUTPUT_BYTES: usize = 1024 * 1024;
const X86_WHITEBOX_PROBE_TIMEOUT: Duration = Duration::from_secs(60);

/// A setup-time proof for the architecture's frozen white-box instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuWhiteboxSetupValidation {
    trap: QemuWhiteboxSetupTrap,
    observed_region: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QemuWhiteboxSetupTrap {
    X86Port,
    Aarch64Hint,
}

impl QemuWhiteboxSetupValidation {
    #[cfg(test)]
    pub(super) fn test_x86_unclaimed() -> Self {
        Self {
            trap: QemuWhiteboxSetupTrap::X86Port,
            observed_region: UNASSIGNED_X86_IO_REGION.to_owned(),
        }
    }

    /// Returns the collision-checked x86 reserved port.
    ///
    /// This compatibility accessor is meaningful only for validation returned
    /// by [`probe_x86_whitebox_setup`].
    #[must_use]
    pub const fn port(&self) -> u16 {
        WHITEBOX_DOORBELL_X86_64_RESERVED_PORT
    }

    /// Returns the QEMU I/O region observed at the reserved port.
    #[must_use]
    pub fn observed_region(&self) -> &str {
        &self.observed_region
    }

    pub(super) const fn attestation(&self) -> &'static str {
        match self.trap {
            QemuWhiteboxSetupTrap::X86Port => super::WHITEBOX_SETUP_X86_PORT_UNCLAIMED_V1,
            QemuWhiteboxSetupTrap::Aarch64Hint => super::WHITEBOX_SETUP_AARCH64_HINT_INERT_V1,
        }
    }

    fn parse_hmp_mtree(output: &str) -> Result<Self, QemuWhiteboxSetupError> {
        let mut in_io_flat_view = false;
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("FlatView #") {
                in_io_flat_view = false;
                continue;
            }
            if trimmed == "AS \"I/O\", root: io" {
                in_io_flat_view = true;
                continue;
            }
            if !in_io_flat_view {
                continue;
            }
            let Some((range, description)) = trimmed.split_once(" (prio ") else {
                continue;
            };
            let Some((start, end)) = range.split_once('-') else {
                continue;
            };
            let (Ok(start), Ok(end)) =
                (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
            else {
                continue;
            };
            let port = u64::from(WHITEBOX_DOORBELL_X86_64_RESERVED_PORT);
            if !(start..=end).contains(&port) {
                continue;
            }
            let Some((_attributes, region)) = description.split_once("): ") else {
                return Err(QemuWhiteboxSetupError::MalformedPortRegion {
                    line: trimmed.to_owned(),
                });
            };
            let region = region
                .split_once(" @")
                .map_or(region, |(name, _offset)| name)
                .trim();
            if region != UNASSIGNED_X86_IO_REGION {
                return Err(QemuWhiteboxSetupError::PortCollision {
                    port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
                    region: region.to_owned(),
                });
            }
            return Ok(Self {
                trap: QemuWhiteboxSetupTrap::X86Port,
                observed_region: region.to_owned(),
            });
        }
        Err(QemuWhiteboxSetupError::ReservedPortAbsent {
            port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
        })
    }
}

/// Validates the retained guest's frozen aarch64 HINT instruction ABI.
///
/// Unlike x86 port I/O, QEMU has no runtime device map for architectural HINT
/// immediates. The versioned retained-guest manifest is therefore the setup
/// authority: ABI v4 reserves HINT `0x4c` for Crucible and guarantees that it is
/// otherwise inert. Callers must obtain the version from retained asset metadata.
///
/// # Errors
///
/// Returns [`QemuWhiteboxSetupError::InstructionAbiMismatch`] when the retained
/// guest declares another instruction ABI.
pub fn validate_aarch64_whitebox_setup(
    instruction_abi_version: u16,
) -> Result<QemuWhiteboxSetupValidation, QemuWhiteboxSetupError> {
    if instruction_abi_version != WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION {
        return Err(QemuWhiteboxSetupError::InstructionAbiMismatch {
            expected: WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
            actual: instruction_abi_version,
        });
    }
    Ok(QemuWhiteboxSetupValidation {
        trap: QemuWhiteboxSetupTrap::Aarch64Hint,
        observed_region: "aarch64-hint-4c-inert".to_owned(),
    })
}

/// Probes the exact stopped QEMU machine and validates its x86 I/O port map.
///
/// The control plugin is removed from the probe process because setup
/// validation must finish before the real process is allowed to register the
/// white-box callback. All machine, firmware, disk, and device arguments remain
/// byte-for-byte identical to the subsequent launch.
///
/// # Errors
///
/// Returns [`QemuWhiteboxSetupError`] when the probe cannot be spawned or
/// controlled, exits unsuccessfully, emits non-UTF-8 monitor output, omits the
/// reserved port, or reports a device region at that port.
pub fn probe_x86_whitebox_setup(
    command: &QemuLaunchCommand,
    run_directory: &Path,
) -> Result<QemuWhiteboxSetupValidation, QemuWhiteboxSetupError> {
    crate::spawn::prepare_vmstate_container(command, run_directory)
        .map_err(|source| QemuWhiteboxSetupError::VmStatePreparation { source })?;
    let args = x86_whitebox_probe_args(command)?;

    let mut child = Command::new(&command.executable)
        .args(&args)
        .current_dir(run_directory)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| QemuWhiteboxSetupError::Spawn { source })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or(QemuWhiteboxSetupError::MonitorStdinUnavailable)?;
    stdin
        .write_all(X86_WHITEBOX_MONITOR_QUERY)
        .map_err(|source| QemuWhiteboxSetupError::MonitorWrite { source })?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|source| QemuWhiteboxSetupError::Wait { source })?;
    validate_x86_whitebox_probe_output(output)
}

/// Probes an admitted QEMU machine under its exact attempt process contract.
///
/// Unlike [`probe_x86_whitebox_setup`], this path consumes an already prepared
/// VMState artifact and launches the stopped probe through the same cgroup,
/// cancellation event, credentials, resource ceilings, and descriptor-pinned
/// directory as the eventual production VM.
///
/// # Errors
///
/// Returns [`QemuWhiteboxSetupError`] when containment admission changes, the
/// bounded probe cannot complete and be reaped, or the reported I/O map fails
/// the same validation as an unguarded probe.
#[cfg(target_os = "linux")]
pub(crate) fn probe_x86_whitebox_setup_guarded(
    command: &QemuLaunchCommand,
    run_directory: &crate::QemuPreparedRunDirectory,
    process_contract: &crate::QemuChildProcessContract,
) -> Result<QemuWhiteboxSetupValidation, QemuWhiteboxSetupError> {
    let args = x86_whitebox_probe_args(command)?;
    let output = crate::spawn::run_guarded_qemu_setup_probe(
        command,
        &args,
        X86_WHITEBOX_MONITOR_QUERY,
        MAXIMUM_X86_WHITEBOX_PROBE_OUTPUT_BYTES,
        X86_WHITEBOX_PROBE_TIMEOUT,
        run_directory,
        process_contract,
    )
    .map_err(|source| QemuWhiteboxSetupError::GuardedProbe { source })?;
    validate_x86_whitebox_probe_output(output)
}

fn x86_whitebox_probe_args(
    command: &QemuLaunchCommand,
) -> Result<Vec<String>, QemuWhiteboxSetupError> {
    let mut args = Vec::with_capacity(command.args.len() + 1);
    let mut index = 0;
    while index < command.args.len() {
        match command.args[index].as_str() {
            "-plugin" => {
                if command.args.get(index + 1).is_none() {
                    return Err(QemuWhiteboxSetupError::MalformedLaunchCommand {
                        option: "-plugin",
                    });
                }
                index += 2;
            }
            "-monitor" => {
                if command.args.get(index + 1).is_none() {
                    return Err(QemuWhiteboxSetupError::MalformedLaunchCommand {
                        option: "-monitor",
                    });
                }
                args.extend(["-monitor".to_owned(), "stdio".to_owned()]);
                index += 2;
            }
            option @ ("-blockdev" | "-drive") => {
                let option = if option == "-blockdev" {
                    "-blockdev"
                } else {
                    "-drive"
                };
                let value = command
                    .args
                    .get(index + 1)
                    .ok_or(QemuWhiteboxSetupError::MalformedLaunchCommand { option })?;
                let read_only = probe_read_only_storage_argument(option, value)?;
                args.extend([option.to_owned(), read_only]);
                index += 2;
            }
            _ => {
                args.push(command.args[index].clone());
                index += 1;
            }
        }
    }
    args.push("-S".to_owned());
    Ok(args)
}

// The setup probe retains the launch's machine and device topology while
// opening its exact storage artifacts read-only. The permission-only change
// prevents QEMU from dirtying a qcow2 header before the real launch.
fn probe_read_only_storage_argument(
    option: &'static str,
    value: &str,
) -> Result<String, QemuWhiteboxSetupError> {
    let supported = match option {
        "-blockdev" => is_vmstate_blockdev(value),
        "-drive" => is_root_overlay_drive(value),
        _ => false,
    };
    if !supported {
        return Err(QemuWhiteboxSetupError::UnsupportedProbeStorageArgument { option });
    }

    let read_only_property = match option {
        "-blockdev" => "read-only=on",
        "-drive" => "readonly=on",
        _ => unreachable!("supported probe storage options are exhaustive"),
    };
    Ok(format!("{value},{read_only_property}"))
}

fn is_vmstate_blockdev(value: &str) -> bool {
    value
        == format!(
            "driver=qcow2,node-name={VMSTATE_DRIVE_ID},file.driver=file,file.filename={DEFAULT_VMSTATE_FILE_NAME}"
        )
}

fn is_root_overlay_drive(value: &str) -> bool {
    let fields = value.split(',').collect::<Vec<_>>();
    let [
        id,
        overlay,
        backing_driver,
        file_driver,
        backing_file,
        interface,
        format,
        cache,
        aio,
        discard,
    ] = fields.as_slice()
    else {
        return false;
    };

    *id == format!("id={ROOT_DRIVE_ID}")
        && overlay
            .strip_prefix("file=")
            .is_some_and(|path| validate_overlay_file_name(path).is_ok())
        && matches!(
            *backing_driver,
            "backing.driver=qcow2" | "backing.driver=raw"
        )
        && *file_driver == "backing.file.driver=file"
        && backing_file
            .strip_prefix("backing.file.filename=")
            .is_some_and(|path| path.starts_with("/nix/store/") && path.len() > "/nix/store/".len())
        && *interface == "if=none"
        && *format == "format=qcow2"
        && *cache == "cache=none"
        && *aio == "aio=threads"
        && *discard == "discard=unmap"
}

fn validate_x86_whitebox_probe_output(
    output: std::process::Output,
) -> Result<QemuWhiteboxSetupValidation, QemuWhiteboxSetupError> {
    if !output.status.success() {
        return Err(QemuWhiteboxSetupError::ProbeExit {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|source| QemuWhiteboxSetupError::MonitorOutputUtf8 { source })?;
    validate_x86_whitebox_hmp_mtree(&stdout)
}

/// Validates one captured QEMU flattened I/O-map report.
///
/// This is the pure parser used by the live setup probe and by its real-QEMU
/// collision negative, so both paths apply the same ownership decision.
///
/// # Errors
///
/// Returns [`QemuWhiteboxSetupError`] when the report is malformed, omits the
/// reserved port, or assigns that port to a device rather than the unassigned
/// QEMU `io` fallback region.
pub fn validate_x86_whitebox_hmp_mtree(
    output: &str,
) -> Result<QemuWhiteboxSetupValidation, QemuWhiteboxSetupError> {
    QemuWhiteboxSetupValidation::parse_hmp_mtree(output)
}

/// A failure while discovering or validating the live x86 I/O port map.
#[derive(Debug, Error)]
pub enum QemuWhiteboxSetupError {
    /// The retained guest asset declares another doorbell instruction ABI.
    #[error("guest doorbell instruction ABI {actual} does not match plugin ABI {expected}")]
    InstructionAbiMismatch {
        /// Instruction ABI required by the plugin.
        expected: u16,
        /// Instruction ABI declared by the guest asset.
        actual: u16,
    },
    /// The stopped probe's exact-VMState container could not be prepared.
    #[error("failed to prepare stopped QEMU white-box VMState container: {source}")]
    VmStatePreparation {
        /// Underlying run-directory or qemu-img failure.
        #[source]
        source: crate::QemuSpawnError,
    },
    /// The contained setup probe violated its attempt or cleanup contract.
    #[cfg(target_os = "linux")]
    #[error("contained QEMU white-box setup probe failed: {source}")]
    GuardedProbe {
        /// Containment, execution, output-bound, or cleanup failure.
        #[source]
        source: crate::spawn::QemuGuardedImagePreparationError,
    },
    /// The launch command ended with an option lacking its value.
    #[error("QEMU launch option `{option}` is missing its value")]
    MalformedLaunchCommand {
        /// Malformed option.
        option: &'static str,
    },
    /// A storage option did not match a form emitted by the launch builder.
    #[error("QEMU launch option `{option}` has an unsupported setup-probe storage form")]
    UnsupportedProbeStorageArgument {
        /// Rejected storage option.
        option: &'static str,
    },
    /// The stopped QEMU probe could not be spawned.
    #[error("failed to spawn stopped QEMU white-box setup probe")]
    Spawn {
        /// Underlying process error.
        #[source]
        source: std::io::Error,
    },
    /// The probe's monitor input pipe was unavailable.
    #[error("stopped QEMU white-box setup probe has no monitor stdin")]
    MonitorStdinUnavailable,
    /// The HMP query could not be written.
    #[error("failed to write QEMU I/O-map monitor query")]
    MonitorWrite {
        /// Underlying pipe error.
        #[source]
        source: std::io::Error,
    },
    /// The probe process could not be reaped.
    #[error("failed to wait for stopped QEMU white-box setup probe")]
    Wait {
        /// Underlying wait error.
        #[source]
        source: std::io::Error,
    },
    /// The probe process rejected the configuration.
    #[error("stopped QEMU white-box setup probe exited with {status}: {stderr}")]
    ProbeExit {
        /// Child exit status.
        status: String,
        /// Captured diagnostic stream.
        stderr: String,
    },
    /// HMP output was not UTF-8.
    #[error("QEMU I/O-map monitor output is not UTF-8")]
    MonitorOutputUtf8 {
        /// UTF-8 conversion error.
        #[source]
        source: std::string::FromUtf8Error,
    },
    /// The line covering the reserved port was malformed.
    #[error("QEMU I/O-map line covering the white-box port is malformed: `{line}`")]
    MalformedPortRegion {
        /// Rejected monitor line.
        line: String,
    },
    /// No I/O-map range covered the frozen port.
    #[error("QEMU I/O map does not cover reserved white-box port {port:#06x}")]
    ReservedPortAbsent {
        /// Missing reserved port.
        port: u16,
    },
    /// A device owns the frozen port.
    #[error("reserved white-box port {port:#06x} collides with QEMU region `{region}`")]
    PortCollision {
        /// Colliding reserved port.
        port: u16,
        /// QEMU memory-region owner.
        region: String,
    },
}

impl QemuWhiteboxSetupError {
    /// Extracts a contained probe whose bounded cleanup could not reap it.
    #[must_use]
    pub(crate) fn take_unreaped_child(&mut self) -> Option<crate::QemuNodeChild> {
        match self {
            #[cfg(target_os = "linux")]
            Self::GuardedProbe { source } => source.take_unreaped_child(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_probe_opens_builder_storage_forms_read_only() {
        let vmstate = format!(
            "driver=qcow2,node-name={VMSTATE_DRIVE_ID},file.driver=file,file.filename={DEFAULT_VMSTATE_FILE_NAME}"
        );
        assert_eq!(
            probe_read_only_storage_argument("-blockdev", &vmstate)
                .unwrap_or_else(|error| panic!("VMState blockdev should validate: {error}")),
            format!("{vmstate},read-only=on")
        );

        for backing_driver in ["qcow2", "raw"] {
            let root = format!(
                "id={ROOT_DRIVE_ID},file=custom-root-overlay.qcow2,backing.driver={backing_driver},backing.file.driver=file,backing.file.filename=/nix/store/00000000000000000000000000000000-root/root.img,if=none,format=qcow2,cache=none,aio=threads,discard=unmap"
            );
            assert_eq!(
                probe_read_only_storage_argument("-drive", &root)
                    .unwrap_or_else(|error| panic!("root drive should validate: {error}")),
                format!("{root},readonly=on")
            );
        }
    }

    #[test]
    fn setup_probe_rejects_storage_forms_the_builder_does_not_emit() {
        for (option, value) in [
            ("-blockdev", "driver=raw,node-name=vmstate"),
            ("-drive", "id=foreign,file=/tmp/disk.img,if=none"),
            (
                "-drive",
                "id=crucible-root,file=overlay.qcow2,backing.driver=qcow2,backing.file.driver=file,backing.file.filename=/tmp/root.img,if=none,format=qcow2,cache=none,aio=threads,discard=unmap",
            ),
        ] {
            assert!(matches!(
                probe_read_only_storage_argument(option, value),
                Err(QemuWhiteboxSetupError::UnsupportedProbeStorageArgument {
                    option: rejected,
                }) if rejected == option
            ));
        }
    }

    #[test]
    fn hmp_mtree_accepts_only_the_unassigned_io_fallback() {
        let output = r#"
FlatView #2
 AS "I/O", root: io
 Root memory region: io
  00000000000000e0-00000000000000ef (prio 0, i/o): io @00000000000000e0
"#;
        let validation = QemuWhiteboxSetupValidation::parse_hmp_mtree(output)
            .unwrap_or_else(|error| panic!("unassigned port should validate: {error}"));
        assert_eq!(validation.port(), WHITEBOX_DOORBELL_X86_64_RESERVED_PORT);
        assert_eq!(validation.observed_region(), "io");
    }

    #[test]
    fn hmp_mtree_rejects_a_real_device_at_the_reserved_port() {
        let output = r#"
FlatView #2
 AS "I/O", root: io
 Root memory region: io
  00000000000000e7-00000000000000e7 (prio 0, i/o): debugcon
"#;
        assert!(matches!(
            QemuWhiteboxSetupValidation::parse_hmp_mtree(output),
            Err(QemuWhiteboxSetupError::PortCollision {
                port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
                region,
            }) if region == "debugcon"
        ));
    }

    #[test]
    fn aarch64_setup_rejects_a_mismatched_guest_instruction_abi() {
        assert!(matches!(
            validate_aarch64_whitebox_setup(WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION - 1),
            Err(QemuWhiteboxSetupError::InstructionAbiMismatch {
                expected: WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
                actual,
            }) if actual == WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION - 1
        ));
    }
}
