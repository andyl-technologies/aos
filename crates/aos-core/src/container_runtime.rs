//! Container initialization synchronization and read-only state detection.
//!
//! The official image starts a short-lived initializer as PID 1 and then
//! `exec`s the requested workload. Container runtimes can launch a second
//! process before that initializer has finished, so an `aos`, `apm`, or `apr`
//! process must not infer readiness merely from the container's running state.
//! This module waits for an init marker bound to the current PID-1 start time,
//! serializes that observation with the init lock, and independently probes
//! writable package state so runtime-created exec processes cannot bypass the
//! read-only boundary by missing PID 1's mutated environment.

use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustix::fs::{FlockOperation, flock};

const RUNTIME_ENV: &str = "AOS_RUNTIME";
const READ_ONLY_ENV: &str = "AOS_CONTAINER_READ_ONLY";
const READY_SCHEMA: &str = "aos.container.ready/v1";
const READ_ONLY_SCHEMA: &str = "aos.container.read-only/v1";
const SYNCHRONIZE_TIMEOUT: Duration = Duration::from_secs(60);
const RETRY_INTERVAL: Duration = Duration::from_millis(10);
static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Describes the reconciled package state of an AOS container.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContainerState {
    read_only: bool,
}

impl ContainerState {
    /// Returns whether package-state mutation is unavailable.
    pub const fn is_read_only(self) -> bool {
        self.read_only
    }
}

#[derive(Clone, Debug)]
struct RuntimePaths {
    state_dir: PathBuf,
    store_dir: PathBuf,
    init_lock: PathBuf,
    ready_marker: PathBuf,
    read_only_marker: PathBuf,
    pid1_stat: PathBuf,
}

impl RuntimePaths {
    fn production() -> Self {
        let state_dir = PathBuf::from("/nix/var/nix");

        Self {
            store_dir: PathBuf::from("/nix/store"),
            init_lock: state_dir.join(".aos-container-init.lock"),
            ready_marker: state_dir.join(".aos-container-ready"),
            read_only_marker: state_dir.join(".aos-container-read-only"),
            pid1_stat: PathBuf::from("/proc/1/stat"),
            state_dir,
        }
    }
}

/// Synchronizes with the official container initializer when applicable.
///
/// A non-container process returns `None` without touching the filesystem.
/// Exact `AOS_RUNTIME=container` processes wait until the initializer has
/// published state for the current PID 1. A fully read-only state directory
/// cannot carry a marker, so it is classified read-only immediately.
///
/// # Errors
///
/// Returns an error when writable container state does not become ready within
/// 60 seconds, the init lock cannot be opened or acquired, PID-1 identity
/// cannot be read, or a persisted read-only marker is malformed.
pub fn synchronize() -> Result<Option<ContainerState>> {
    if std::env::var_os(RUNTIME_ENV).as_deref() != Some(OsStr::new("container")) {
        return Ok(None);
    }

    let environment_read_only = std::env::var_os(READ_ONLY_ENV).as_deref() == Some(OsStr::new("1"));
    synchronize_paths(
        &RuntimePaths::production(),
        environment_read_only,
        SYNCHRONIZE_TIMEOUT,
    )
    .map(Some)
}

fn synchronize_paths(
    paths: &RuntimePaths,
    environment_read_only: bool,
    timeout: Duration,
) -> Result<ContainerState> {
    if !directory_is_writable(&paths.state_dir) {
        return Ok(ContainerState { read_only: true });
    }

    let pid1_start_time = read_start_time(&paths.pid1_stat)?;
    wait_for_ready(paths, &pid1_start_time, timeout)?;

    let persisted_read_only = read_read_only_marker(&paths.read_only_marker)?;
    let store_writable = directory_is_writable(&paths.store_dir);

    Ok(ContainerState {
        read_only: environment_read_only || persisted_read_only || !store_writable,
    })
}

fn wait_for_ready(paths: &RuntimePaths, pid1_start_time: &str, timeout: Duration) -> Result<()> {
    let mut remaining = timeout;

    loop {
        if ready_marker_matches(&paths.ready_marker, pid1_start_time)? {
            match File::open(&paths.init_lock) {
                Ok(lock) => {
                    flock(&lock, FlockOperation::LockShared).with_context(|| {
                        format!(
                            "locking container initialization at {}",
                            paths.init_lock.display()
                        )
                    })?;

                    if ready_marker_matches(&paths.ready_marker, pid1_start_time)? {
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("opening container init lock {}", paths.init_lock.display())
                    });
                }
            }
        }

        if remaining.is_zero() {
            bail!(
                "AOS container initialization did not become ready within {} seconds",
                timeout.as_secs()
            );
        }
        let retry_after = remaining.min(RETRY_INTERVAL);
        std::thread::sleep(retry_after);
        remaining = remaining.saturating_sub(retry_after);
    }
}

fn ready_marker_matches(path: &Path, pid1_start_time: &str) -> Result<bool> {
    let expected = format!("schema={READY_SCHEMA}\npid1_start_time={pid1_start_time}\n");
    match fs::read(path) {
        Ok(bytes) => Ok(bytes == expected.as_bytes()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("reading container readiness marker {}", path.display())),
    }
}

fn read_read_only_marker(path: &Path) -> Result<bool> {
    let expected = format!("schema={READ_ONLY_SCHEMA}\n");
    match fs::read(path) {
        Ok(bytes) if bytes == expected.as_bytes() => Ok(true),
        Ok(_) => bail!("container read-only marker {} is malformed", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("reading container read-only marker {}", path.display())),
    }
}

fn read_start_time(path: &Path) -> Result<String> {
    let stat = fs::read_to_string(path)
        .with_context(|| format!("reading PID-1 identity from {}", path.display()))?;
    let command_end = stat
        .rfind(") ")
        .with_context(|| format!("PID-1 stat {} has no command terminator", path.display()))?;
    let start_time = stat[command_end + 2..]
        .split_whitespace()
        .nth(19)
        .with_context(|| format!("PID-1 stat {} omits start time", path.display()))?;
    if start_time.is_empty() || !start_time.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("PID-1 stat {} has an invalid start time", path.display());
    }

    Ok(start_time.to_string())
}

fn directory_is_writable(path: &Path) -> bool {
    for _ in 0..4 {
        let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let probe = path.join(format!(
            ".aos-container-runtime-probe-{}-{sequence}",
            std::process::id()
        ));
        match fs::create_dir(&probe) {
            Ok(()) => return fs::remove_dir(&probe).is_ok(),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return false,
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_paths(root: &Path) -> RuntimePaths {
        let state_dir = root.join("nix/var/nix");
        RuntimePaths {
            store_dir: root.join("nix/store"),
            init_lock: state_dir.join(".aos-container-init.lock"),
            ready_marker: state_dir.join(".aos-container-ready"),
            read_only_marker: state_dir.join(".aos-container-read-only"),
            pid1_stat: root.join("proc/1/stat"),
            state_dir,
        }
    }

    fn prepare_runtime(root: &Path, token: &str) -> RuntimePaths {
        let paths = runtime_paths(root);
        fs::create_dir_all(&paths.state_dir).expect("state directory");
        fs::create_dir_all(&paths.store_dir).expect("store directory");
        fs::create_dir_all(paths.pid1_stat.parent().expect("stat parent")).expect("proc directory");
        fs::write(&paths.init_lock, []).expect("init lock");
        fs::write(
            &paths.ready_marker,
            format!("schema={READY_SCHEMA}\npid1_start_time={token}\n"),
        )
        .expect("ready marker");
        fs::write(
            &paths.pid1_stat,
            format!("1 (aos init) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {token} 0\n"),
        )
        .expect("PID-1 stat");
        paths
    }

    #[test]
    fn synchronized_writable_state_is_mutable() {
        let temp = tempfile::tempdir().expect("temporary root");
        let paths = prepare_runtime(temp.path(), "4242");

        let state = synchronize_paths(&paths, false, Duration::from_millis(50))
            .expect("synchronized runtime");

        assert!(!state.is_read_only());
    }

    #[test]
    fn persisted_marker_makes_exec_processes_read_only() {
        let temp = tempfile::tempdir().expect("temporary root");
        let paths = prepare_runtime(temp.path(), "4343");
        fs::write(
            &paths.read_only_marker,
            format!("schema={READ_ONLY_SCHEMA}\n"),
        )
        .expect("read-only marker");

        let state = synchronize_paths(&paths, false, Duration::from_millis(50))
            .expect("synchronized runtime");

        assert!(state.is_read_only());
    }

    #[test]
    fn unwritable_state_is_read_only_without_a_marker() {
        let temp = tempfile::tempdir().expect("temporary root");
        let paths = runtime_paths(temp.path());
        fs::create_dir_all(paths.state_dir.parent().expect("state parent"))
            .expect("state parent directory");
        fs::write(&paths.state_dir, b"not a directory").expect("state sentinel");

        let state =
            synchronize_paths(&paths, false, Duration::from_millis(50)).expect("read-only runtime");

        assert!(state.is_read_only());
    }

    #[test]
    fn stale_ready_marker_times_out() {
        let temp = tempfile::tempdir().expect("temporary root");
        let paths = prepare_runtime(temp.path(), "4444");
        fs::write(
            &paths.ready_marker,
            format!("schema={READY_SCHEMA}\npid1_start_time=old\n"),
        )
        .expect("stale marker");

        let error = synchronize_paths(&paths, false, Duration::from_millis(1))
            .expect_err("stale marker must not admit a new PID 1");

        assert!(error.to_string().contains("did not become ready"));
    }
}
