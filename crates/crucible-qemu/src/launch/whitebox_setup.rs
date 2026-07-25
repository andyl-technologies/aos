//! Live QEMU x86 doorbell-port collision discovery.
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

use crucible_protocol::WHITEBOX_DOORBELL_X86_64_RESERVED_PORT;
use thiserror::Error;

use super::QemuLaunchCommand;

const UNASSIGNED_X86_IO_REGION: &str = "io";

/// A setup-time proof that the frozen x86 doorbell port is unclaimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuWhiteboxSetupValidation {
    port: u16,
    observed_region: String,
}

impl QemuWhiteboxSetupValidation {
    /// Returns the collision-checked reserved port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the QEMU I/O region observed at the reserved port.
    #[must_use]
    pub fn observed_region(&self) -> &str {
        &self.observed_region
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
                port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
                observed_region: region.to_owned(),
            });
        }
        Err(QemuWhiteboxSetupError::ReservedPortAbsent {
            port: WHITEBOX_DOORBELL_X86_64_RESERVED_PORT,
        })
    }
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
}
