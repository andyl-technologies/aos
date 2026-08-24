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
};

use crucible_protocol::{
    WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION, WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
};
use thiserror::Error;

use super::QemuLaunchCommand;

const UNASSIGNED_X86_IO_REGION: &str = "io";

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
            _ => {
                args.push(command.args[index].clone());
                index += 1;
            }
        }
    }
    args.push("-S".to_owned());

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
        .write_all(b"info mtree -f\nquit\n")
        .map_err(|source| QemuWhiteboxSetupError::MonitorWrite { source })?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|source| QemuWhiteboxSetupError::Wait { source })?;
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
    /// The launch command ended with an option lacking its value.
    #[error("QEMU launch option `{option}` is missing its value")]
    MalformedLaunchCommand {
        /// Malformed option.
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

#[cfg(test)]
mod tests {
    use super::*;

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
