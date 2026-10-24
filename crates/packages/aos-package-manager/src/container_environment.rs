//! Initializes retained image state when a container command bypasses its entrypoint.
//!
//! Dockerfile `RUN` instructions do not execute the image entrypoint. The image
//! retains a setup helper that registers its embedded store closure and seeds
//! package generations without starting services. Ordinary APM commands run that
//! helper before waiting for container readiness; private deployment commands
//! invoked by the helper must avoid this path to prevent recursive locking.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, ensure};

static PROBE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const SETUP_PATH: &str = "/usr/lib/aos-container/setup";
const READY_PATH: &str = "/nix/var/nix/.aos-container-ready";
const PID1_STAT_PATH: &str = "/proc/1/stat";

/// Initializes the official image's retained package state when necessary.
///
/// # Errors
///
/// Returns an error when PID-1 identity cannot be read, retained setup is
/// unavailable, or image setup fails. Non-root processes leave initialization
/// to the image entrypoint and synchronize through the ordinary runtime gate.
pub(crate) fn prepare() -> Result<()> {
    if !crate::runtime_boundary::is_container()
        || !rustix::process::geteuid().is_root()
        || std::env::var_os("AOS_CONTAINER_READ_ONLY").as_deref() == Some(std::ffi::OsStr::new("1"))
        || current_process_ready(Path::new(READY_PATH), Path::new(PID1_STAT_PATH))?
    {
        return Ok(());
    }

    // A completely read-only image still supports baked queries. The runtime
    // gate probes actual writability and reports this state independently.
    if !package_state_writable() {
        return Ok(());
    }
    ensure!(
        Path::new(SETUP_PATH).is_file(),
        "retained AOS container setup is missing: {SETUP_PATH}"
    );

    let status = Command::new(SETUP_PATH)
        .arg("--setup-only")
        .status()
        .context("initializing retained AOS container package state")?;
    ensure!(
        status.success(),
        "AOS container package setup failed: {status}"
    );
    Ok(())
}

/// Selects effect phases from the currently established container runtime.
///
/// # Errors
///
/// Returns an error when the container service readiness identity is unreadable.
pub(crate) fn policy() -> Result<aos_activation::activation::ExecutionPolicy> {
    use aos_activation::activation::ExecutionPolicy;

    if !crate::runtime_boundary::is_container() || service_runtime_ready()? {
        Ok(ExecutionPolicy::Complete)
    } else {
        Ok(ExecutionPolicy::Installation)
    }
}

/// Selects lifecycle phases without mistaking a new init selection for running init.
///
/// # Errors
/// Returns an error for unreadable readiness/configuration or invalid init selection.
pub(crate) fn policy_for_deployment(
    deployment: &aos_deployment_format::model::Deployment,
) -> Result<aos_activation::activation::ExecutionPolicy> {
    use aos_activation::activation::ExecutionPolicy;

    let policy = policy()?;
    if !crate::runtime_boundary::is_container() || policy == ExecutionPolicy::Installation {
        return Ok(policy);
    }
    // Installation may replace init.json during this transaction. Service
    // handlers must wait for a restart when that candidate selects a new init.
    if crate::container_runtime::candidate_init_matches(deployment)? {
        Ok(ExecutionPolicy::Complete)
    } else {
        Ok(ExecutionPolicy::Installation)
    }
}

/// Probes the package roots before setup or readiness waiting can run.
pub(crate) fn package_state_writable() -> bool {
    ["/nix/store", "/nix/var/nix", "/var/lib/apm"]
        .into_iter()
        .all(|path| directory_is_writable(Path::new(path)))
}

/// Reports whether the selected init is running with activated service phases.
///
/// # Errors
///
/// Returns an error when the selected init configuration, service readiness
/// marker, or PID-1 identity cannot be read. Missing markers and a selection
/// that differs from the running init report an installation-only runtime.
pub(crate) fn service_runtime_ready() -> Result<bool> {
    crate::container_runtime::service_ready(
        Path::new("/run/aos/container-service-ready"),
        Path::new(PID1_STAT_PATH),
        Path::new("/proc/1/exe"),
        Path::new("/etc/aos/init.json"),
    )
}

fn directory_is_writable(path: &Path) -> bool {
    let sequence = PROBE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let probe = path.join(format!(
        ".aos-apm-setup-probe-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir(&probe).is_ok() && fs::remove_dir(&probe).is_ok()
}

fn current_process_ready(marker: &Path, stat: &Path) -> Result<bool> {
    current_process_ready_with_schema(marker, stat, "aos.container.ready/v1")
}

fn current_process_ready_with_schema(marker: &Path, stat: &Path, schema: &str) -> Result<bool> {
    let bytes = match fs::read(marker) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", marker.display()));
        }
    };
    let stat = fs::read_to_string(stat).context("reading container PID-1 identity")?;
    let (_, fields) = stat
        .rsplit_once(") ")
        .context("container PID-1 identity has no command terminator")?;
    let start_time = fields
        .split_whitespace()
        .nth(19)
        .context("container PID-1 identity omits its start time")?;
    ensure!(
        start_time.bytes().all(|byte| byte.is_ascii_digit()),
        "container PID-1 identity has an invalid start time"
    );

    Ok(bytes == format!("schema={schema}\npid1_start_time={start_time}\n").as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_readiness_is_bound_to_the_current_pid1_lifetime() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("ready");
        let stat = root.path().join("stat");
        fs::write(
            &stat,
            "1 (command with ) parentheses) S 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4242 0\n",
        )
        .unwrap();
        assert!(!current_process_ready(&marker, &stat).unwrap());

        fs::write(
            &marker,
            "schema=aos.container.ready/v1\npid1_start_time=old\n",
        )
        .unwrap();
        assert!(!current_process_ready(&marker, &stat).unwrap());

        fs::write(
            &marker,
            "schema=aos.container.ready/v1\npid1_start_time=4242\n",
        )
        .unwrap();
        assert!(current_process_ready(&marker, &stat).unwrap());
        assert!(
            !current_process_ready_with_schema(&marker, &stat, "aos.container.service-ready/v1")
                .unwrap()
        );

        fs::write(
            &marker,
            "schema=aos.container.service-ready/v1\npid1_start_time=4242\n",
        )
        .unwrap();
        assert!(
            current_process_ready_with_schema(&marker, &stat, "aos.container.service-ready/v1")
                .unwrap()
        );
    }
}
