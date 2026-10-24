//! Live crucible-shmem block-driver realization gate.
//!
//! Boots the patched QEMU binary with a crucible-shmem virtio-blk device
//! attached through the typed `-blockdev driver=crucible-shmem` interface and the
//! CPU frozen at reset (`-S`), negotiates QMP, and asserts the VM reached the
//! `prelaunch` run state. Reaching prelaunch proves QEMU parsed the driver name,
//! ran `bdrv_open` on the crucible-shmem node, and realized the virtio-blk
//! front-end without the driver name being rejected -- the durable regression
//! guard that the crucible-shmem block driver stays registered and openable.
//!
//! The guest never executes (it stays frozen at reset), so no guest block I/O
//! is issued and the device needs no host ring-servicer to realize. That makes
//! this a pure registration/open probe, distinct from the live block I/O path.
//!
//! Evidence fields printed by the gate example and asserted by the nix gate:
//!
//! ```text
//! PASS
//! gate=gate:block-realization
//! driver_opened=true
//! run_state=prelaunch
//! orderly_child_exit=true
//! ```

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;

use thiserror::Error;

use crate::launch::CrucibleShmemBlockDevice;
use crate::qmp::{QmpClient, QmpError, QmpRunStateKind};

/// Fixed QMP socket file name created in the run directory.
const QMP_SOCKET_FILE_NAME: &str = "crucible-block-realization-qmp.sock";
/// Standard output log file name for the spawned QEMU child.
const STDOUT_LOG_FILE_NAME: &str = "qemu-stdout.log";
/// Standard error log file name for the spawned QEMU child.
const STDERR_LOG_FILE_NAME: &str = "qemu-stderr.log";
/// Delay between QMP socket connection attempts while QEMU starts up.
const QMP_CONNECT_POLL_DELAY: Duration = Duration::from_millis(50);
/// Maximum QMP connection attempts (about 20 seconds at the poll delay).
const QMP_CONNECT_MAX_ATTEMPTS: u32 = 400;
/// Delay between child-exit polls after a graceful QMP `quit`.
const CHILD_EXIT_POLL_DELAY: Duration = Duration::from_millis(20);
/// Maximum child-exit polls after a quit (about 10 seconds at the poll delay).
const CHILD_EXIT_MAX_POLLS: u32 = 500;

/// Inputs for one live crucible-shmem block-driver realization gate run.
#[derive(Clone, Debug)]
pub struct BlockRealizationGateConfig {
    qemu: String,
    run_directory: PathBuf,
    device: CrucibleShmemBlockDevice,
}

impl BlockRealizationGateConfig {
    /// Builds a config that attaches a crucible-shmem device of `size_bytes`.
    #[must_use]
    pub fn new(
        qemu: impl Into<String>,
        run_directory: impl Into<PathBuf>,
        size_bytes: u64,
    ) -> Self {
        Self {
            qemu: qemu.into(),
            run_directory: run_directory.into(),
            device: CrucibleShmemBlockDevice::new(size_bytes),
        }
    }

    /// Returns a config that attaches an explicitly configured device.
    #[must_use]
    pub fn with_device(mut self, device: CrucibleShmemBlockDevice) -> Self {
        self.device = device;
        self
    }
}

/// Machine-checkable outcome of a realization gate run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRealizationReport {
    /// Whether the crucible-shmem node opened and the VM reached prelaunch.
    pub driver_opened: bool,
    /// Observed QMP run state name.
    pub run_state: &'static str,
    /// Whether the QEMU child exited cleanly after a graceful QMP quit.
    pub orderly_child_exit: bool,
}

/// Runs the live crucible-shmem block-driver realization gate.
///
/// Spawns QEMU with the crucible-shmem device attached and the CPU frozen,
/// negotiates QMP, asserts the prelaunch run state, then quits gracefully and
/// waits for an orderly child exit.
///
/// # Errors
///
/// Returns [`BlockRealizationGateError`] when the device inputs are invalid, the
/// QEMU path is not an AOS store path, the child cannot be spawned, QMP cannot
/// connect within the connect budget, the observed run state is not prelaunch,
/// or the child does not exit cleanly after a graceful quit.
pub fn run_block_realization_gate(
    config: &BlockRealizationGateConfig,
) -> Result<BlockRealizationReport, BlockRealizationGateError> {
    validate_store_path(&config.qemu)?;
    config
        .device
        .validate()
        .map_err(|source| BlockRealizationGateError::InvalidDevice {
            detail: source.to_string(),
        })?;

    let run_directory = config.run_directory.as_path();
    let socket_path = run_directory.join(QMP_SOCKET_FILE_NAME);
    let argv = build_probe_argv(&config.device, QMP_SOCKET_FILE_NAME);

    let mut child = spawn_frozen_qemu(&config.qemu, run_directory, &argv)?;
    let outcome = drive_qmp_probe(&socket_path);
    finalize(&mut child, outcome)
}

/// Assembles the fixed probe argv around the crucible-shmem device pair.
fn build_probe_argv(device: &CrucibleShmemBlockDevice, socket_file_name: &str) -> Vec<String> {
    let mut argv = vec![
        "-machine".to_owned(),
        "q35".to_owned(),
        "-accel".to_owned(),
        "tcg".to_owned(),
        "-m".to_owned(),
        "128".to_owned(),
        "-S".to_owned(),
        "-nographic".to_owned(),
        "-serial".to_owned(),
        "none".to_owned(),
        "-qmp".to_owned(),
        format!("unix:{socket_file_name},server=on,wait=off"),
    ];
    device.append_qemu_args(&mut argv);
    argv
}

/// Spawns QEMU with a cleared environment, frozen CPU, and logs in `directory`.
fn spawn_frozen_qemu(
    qemu: &str,
    directory: &Path,
    argv: &[String],
) -> Result<std::process::Child, BlockRealizationGateError> {
    let stdout = create_log(directory, STDOUT_LOG_FILE_NAME)?;
    let stderr = create_log(directory, STDERR_LOG_FILE_NAME)?;
    let mut command = Command::new(qemu);
    command
        .arg0(qemu)
        .args(argv)
        .current_dir(directory)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    command
        .spawn()
        .map_err(|source| BlockRealizationGateError::Spawn {
            detail: source.to_string(),
        })
}

/// Connects QMP within the connect budget and reads the run state.
fn drive_qmp_probe(socket_path: &Path) -> Result<QmpProbe, BlockRealizationGateError> {
    let mut client = connect_qmp_when_ready(socket_path)?;
    let run_state = client
        .query_status()
        .map_err(|source| BlockRealizationGateError::Qmp { source })?;
    let driver_opened = !run_state.running && run_state.status == QmpRunStateKind::Prelaunch;
    // Ask QEMU to exit whether or not the state matched, so the child never
    // outlives the gate; the state assertion is reported to the caller.
    let quit = client
        .quit()
        .map_err(|source| BlockRealizationGateError::Qmp { source });
    quit.map(|_| QmpProbe {
        driver_opened,
        run_state: run_state_wire_name(run_state.status),
    })
}

/// Maps a typed QMP run state to its QEMU wire name for evidence reporting.
const fn run_state_wire_name(kind: QmpRunStateKind) -> &'static str {
    match kind {
        QmpRunStateKind::Debug => "debug",
        QmpRunStateKind::FinishMigrate => "finish-migrate",
        QmpRunStateKind::InMigrate => "inmigrate",
        QmpRunStateKind::InternalError => "internal-error",
        QmpRunStateKind::IoError => "io-error",
        QmpRunStateKind::Paused => "paused",
        QmpRunStateKind::PostMigrate => "postmigrate",
        QmpRunStateKind::Prelaunch => "prelaunch",
        QmpRunStateKind::RestoreVm => "restore-vm",
        QmpRunStateKind::Running => "running",
        QmpRunStateKind::SaveVm => "save-vm",
        QmpRunStateKind::Shutdown => "shutdown",
        QmpRunStateKind::Suspended => "suspended",
        QmpRunStateKind::Watchdog => "watchdog",
        QmpRunStateKind::GuestPanicked => "guest-panicked",
        QmpRunStateKind::Colo => "colo",
    }
}

/// Retries the QMP Unix-socket connection until it succeeds or attempts lapse.
///
/// A bounded attempt count -- rather than a host wall-clock deadline -- keeps
/// the child startup wait deterministic in shape and free of host time inputs.
fn connect_qmp_when_ready(
    socket_path: &Path,
) -> Result<QmpClient<UnixStream>, BlockRealizationGateError> {
    let mut last_error = None;
    for attempt in 0..QMP_CONNECT_MAX_ATTEMPTS {
        match QmpClient::connect_unix_socket(socket_path) {
            Ok(client) => return Ok(client),
            Err(source) => {
                last_error = Some(source);
                if attempt + 1 < QMP_CONNECT_MAX_ATTEMPTS {
                    thread::sleep(QMP_CONNECT_POLL_DELAY);
                }
            }
        }
    }
    Err(BlockRealizationGateError::QmpConnect {
        source: last_error.unwrap_or(QmpError::UnboundedTimeout {
            operation: "connect QMP Unix socket",
        }),
    })
}

/// Waits for the child to exit after quit and folds the probe into a report.
fn finalize(
    child: &mut std::process::Child,
    outcome: Result<QmpProbe, BlockRealizationGateError>,
) -> Result<BlockRealizationReport, BlockRealizationGateError> {
    let probe = match outcome {
        Ok(probe) => probe,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let orderly_child_exit = wait_for_clean_exit(child);
    if !probe.driver_opened {
        return Err(BlockRealizationGateError::UnexpectedRunState {
            run_state: probe.run_state,
        });
    }
    Ok(BlockRealizationReport {
        driver_opened: true,
        run_state: probe.run_state,
        orderly_child_exit,
    })
}

/// Polls the child for a clean exit within a bounded poll count, killing on timeout.
fn wait_for_clean_exit(child: &mut std::process::Child) -> bool {
    for _ in 0..CHILD_EXIT_MAX_POLLS {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => thread::sleep(CHILD_EXIT_POLL_DELAY),
            Err(_) => return false,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    false
}

/// Creates a fresh log file under `directory`, failing if it already exists.
fn create_log(directory: &Path, name: &'static str) -> Result<File, BlockRealizationGateError> {
    File::options()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .map_err(|source| BlockRealizationGateError::Log {
            name,
            detail: source.to_string(),
        })
}

/// Rejects any QEMU path that is not an AOS store path.
fn validate_store_path(path: &str) -> Result<(), BlockRealizationGateError> {
    if path.starts_with("/nix/store/") && !path.contains(',') && !path.contains('\n') {
        Ok(())
    } else {
        Err(BlockRealizationGateError::NonStoreQemu {
            path: path.to_owned(),
        })
    }
}

/// Internal QMP probe outcome before the child-exit wait.
struct QmpProbe {
    driver_opened: bool,
    run_state: &'static str,
}

/// Error returned by the live crucible-shmem block realization gate.
#[derive(Debug, Error)]
pub enum BlockRealizationGateError {
    /// The crucible-shmem device inputs failed validation.
    #[error("invalid crucible-shmem device: {detail}")]
    InvalidDevice {
        /// Validation failure detail.
        detail: String,
    },
    /// The QEMU path was not an AOS store path.
    #[error("qemu executable must be an AOS store path, got `{path}`")]
    NonStoreQemu {
        /// Rejected executable path.
        path: String,
    },
    /// A run-directory log file could not be created.
    #[error("create {name} log failed: {detail}")]
    Log {
        /// Log file name.
        name: &'static str,
        /// Underlying I/O error text.
        detail: String,
    },
    /// QEMU could not be spawned.
    #[error("spawn frozen QEMU failed: {detail}")]
    Spawn {
        /// Underlying spawn error text.
        detail: String,
    },
    /// The QMP socket did not accept a connection within the budget.
    #[error("QMP connect failed: {source}")]
    QmpConnect {
        /// Underlying QMP connection error.
        source: QmpError,
    },
    /// A QMP command failed.
    #[error("QMP command failed: {source}")]
    Qmp {
        /// Underlying QMP command error.
        source: QmpError,
    },
    /// The VM did not reach the prelaunch run state.
    #[error("expected prelaunch run state, observed `{run_state}`")]
    UnexpectedRunState {
        /// Observed run state wire name.
        run_state: &'static str,
    },
}
