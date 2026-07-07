//! Out-of-band QEMU launch-channel configuration.
//!
//! This module owns control-plane launch channels that are outside the
//! scheduler hot path. The gdbstub channel is operator-mediated debugging, and
//! QMP is machine control for snapshot and shutdown operations.

use std::path::{Path, PathBuf};

use super::validation::{QemuPreSpawnLaunchValidationError, option_values, unique_comma_value};
use super::{QemuLaunchCommandError, validate_launch_text};

/// Configuration for the debug-session QEMU gdbstub proxy channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuGdbstubChannelConfig {
    qemu_endpoint: String,
    operator_listen: String,
}

impl QemuGdbstubChannelConfig {
    /// Builds a validated gdbstub proxy channel configuration.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError`] when either endpoint is empty or
    /// contains a newline or NUL byte.
    pub fn new(
        qemu_endpoint: impl Into<String>,
        operator_listen: impl Into<String>,
    ) -> Result<Self, QemuLaunchCommandError> {
        let config = Self {
            qemu_endpoint: qemu_endpoint.into(),
            operator_listen: operator_listen.into(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Returns the raw endpoint passed to QEMU's `-gdb` option.
    #[must_use]
    pub fn qemu_endpoint(&self) -> &str {
        &self.qemu_endpoint
    }

    /// Returns the operator-facing `--gdb-listen` endpoint owned by the proxy.
    #[must_use]
    pub fn operator_listen(&self) -> &str {
        &self.operator_listen
    }

    /// Returns whether Crucible mediates the QEMU gdbstub to the operator endpoint.
    #[must_use]
    pub const fn mediated_by_crucible(&self) -> bool {
        true
    }

    /// Returns whether the gdbstub channel is outside the scheduler hot path.
    #[must_use]
    pub const fn out_of_band(&self) -> bool {
        true
    }

    /// Returns whether debugger traffic carries per-quantum timing data.
    #[must_use]
    pub const fn carries_per_quantum_timing(&self) -> bool {
        false
    }

    /// Returns whether debugger traffic carries guest frame data.
    #[must_use]
    pub const fn carries_frame_data(&self) -> bool {
        false
    }

    /// Validates the launch/proxy endpoint strings.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError::InvalidLaunchText`] when an endpoint is
    /// empty or contains a newline or NUL byte.
    pub fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_launch_text("qemu_gdbstub_endpoint", &self.qemu_endpoint)?;
        validate_launch_text("gdb_listen_endpoint", &self.operator_listen)
    }
}

/// Configuration for the QMP machine-control Unix socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuQmpChannelConfig {
    socket_file_name: String,
}

impl QemuQmpChannelConfig {
    /// Builds a validated QMP Unix socket channel configuration.
    ///
    /// The socket path is modeled as a stable relative file name. A later node
    /// factory can place the child in a run directory and connect to this
    /// socket without embedding host-temporary paths in QEMU argv.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLaunchCommandError`] when `socket_file_name` is empty,
    /// contains unstable text, or is not a relative file name.
    pub fn new(socket_file_name: impl Into<String>) -> Result<Self, QemuLaunchCommandError> {
        let config = Self {
            socket_file_name: socket_file_name.into(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Returns the stable relative socket file name.
    #[must_use]
    pub fn socket_file_name(&self) -> &str {
        &self.socket_file_name
    }

    /// Resolves the host-side socket path inside a caller-owned run directory.
    ///
    /// The launch argument intentionally carries only [`Self::socket_file_name`]
    /// so volatile host paths do not enter QEMU argv or launch hash material.
    /// The node factory owns `run_directory` and uses this path to connect the
    /// typed QMP client after spawn.
    #[must_use]
    pub fn socket_path(&self, run_directory: impl AsRef<Path>) -> PathBuf {
        run_directory.as_ref().join(&self.socket_file_name)
    }

    /// Returns the QEMU `-qmp` endpoint string.
    #[must_use]
    pub fn qemu_endpoint(&self) -> String {
        format!("unix:{},server=on,wait=off", self.socket_file_name)
    }

    /// Returns whether QMP is outside the scheduler hot path.
    #[must_use]
    pub const fn out_of_band(&self) -> bool {
        true
    }

    /// Returns whether QMP carries per-quantum timing data.
    #[must_use]
    pub const fn carries_per_quantum_timing(&self) -> bool {
        false
    }

    /// Returns whether QMP carries guest frame data.
    #[must_use]
    pub const fn carries_frame_data(&self) -> bool {
        false
    }

    pub(super) fn validate(&self) -> Result<(), QemuLaunchCommandError> {
        validate_qmp_socket_file_name(&self.socket_file_name)
    }
}

pub(super) fn validate_optional_pre_spawn_qmp_control_endpoint(
    args: &[String],
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    let values = option_values(args, "-qmp")?;
    match values.as_slice() {
        [] => Ok(()),
        [qmp] => validate_pre_spawn_qmp_control_endpoint(qmp),
        _ => Err(QemuPreSpawnLaunchValidationError::DuplicateOption { option: "-qmp" }),
    }
}

fn validate_pre_spawn_qmp_control_endpoint(
    qmp: &str,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    if !qmp_endpoint_text_is_stable(qmp) {
        return Err(qmp_endpoint_error(qmp, "unstable QMP endpoint text"));
    }
    let Some(endpoint_tail) = qmp.strip_prefix("unix:") else {
        return Err(qmp_endpoint_error(qmp, "non-Unix QMP control channel"));
    };
    let socket_file_name = endpoint_tail.split(',').next().unwrap_or_default();
    validate_pre_spawn_qmp_socket_file_name(socket_file_name, qmp)?;
    validate_qmp_suboption_keys(qmp)?;
    let lower = qmp.to_ascii_lowercase();

    if unique_comma_value(&lower, "-qmp", "server")? != Some("on") {
        return Err(qmp_endpoint_error(
            qmp,
            "QMP channel without host-owned server endpoint",
        ));
    }
    if unique_comma_value(&lower, "-qmp", "wait")? != Some("off") {
        return Err(qmp_endpoint_error(
            qmp,
            "QMP channel that can block deterministic launch",
        ));
    }
    Ok(())
}

fn validate_qmp_suboption_keys(qmp: &str) -> Result<(), QemuPreSpawnLaunchValidationError> {
    for suboption in qmp.split(',').skip(1) {
        let key = suboption.split_once('=').map(|(key, _value)| key.trim());
        match key {
            Some("server" | "wait") => {}
            _ => {
                return Err(qmp_endpoint_error(
                    qmp,
                    "unsupported QMP control channel option",
                ));
            }
        }
    }
    Ok(())
}

fn validate_qmp_socket_file_name(file_name: &str) -> Result<(), QemuLaunchCommandError> {
    validate_launch_text("qmp_socket_file_name", file_name)?;
    if qmp_socket_file_name_is_stable(file_name) {
        Ok(())
    } else {
        Err(QemuLaunchCommandError::InvalidQmpSocketFileName {
            file_name: file_name.to_owned(),
        })
    }
}

fn validate_pre_spawn_qmp_socket_file_name(
    socket_file_name: &str,
    qmp: &str,
) -> Result<(), QemuPreSpawnLaunchValidationError> {
    if !qmp_socket_file_name_is_stable(socket_file_name) {
        Err(qmp_endpoint_error(qmp, "unstable QMP socket file name"))
    } else {
        Ok(())
    }
}

fn qmp_socket_file_name_is_stable(file_name: &str) -> bool {
    !file_name.is_empty()
        && qmp_endpoint_text_is_stable(file_name)
        && file_name != "."
        && file_name != ".."
        && !file_name.contains('/')
        && !file_name.contains('\\')
        && !file_name.contains(',')
        && !file_name.contains(':')
}

fn qmp_endpoint_text_is_stable(text: &str) -> bool {
    !text.contains('\n') && !text.contains('\0')
}

fn qmp_endpoint_error(qmp: &str, reason: &'static str) -> QemuPreSpawnLaunchValidationError {
    QemuPreSpawnLaunchValidationError::HostTimingOrEntropyArgument {
        argument: format!("-qmp {qmp}"),
        reason,
    }
}
