//! Tests extracted from the adjacent production module.

use std::env;
use std::error::Error;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::*;

const PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_CHILD_PROBE";
const SOURCE_FDS_ENV: &str = "CRUCIBLE_QEMU_SPAWN_SOURCE_FDS";
const CWD_PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_CWD_PROBE";
const PDEATH_PARENT_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_PARENT_PROBE";
const PDEATH_CHILD_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PROBE";
const PDEATH_CHILD_PID_PREFIX: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PID=";
const ENV_CLEAR_PARENT_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_PARENT_PROBE";
const ENV_CLEAR_CHILD_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_CHILD_PROBE";
const INHERITED_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_INHERITED_SENTINEL";
const EXPLICIT_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_EXPLICIT_SENTINEL";
static TEMP_DIR_SUFFIX: AtomicU64 = AtomicU64::new(0);

#[test]
fn qemu_spawn_resources_create_socket_memfd_eventfd_and_host_copies() -> Result<(), Box<dyn Error>>
{
    let (resources, child_resources) = create_spawn_resources(4096)?;

    assert_eq!(resources.region_len(), 4096);
    assert_fd_open(resources.control_socket_fd())?;
    assert_fd_open(resources.shmem_fd())?;
    assert_fd_open(resources.wake_fd())?;
    assert_fd_open(child_resources.control_socket.as_raw_fd())?;
    assert_fd_open(child_resources.shmem_fd.as_raw_fd())?;
    assert_fd_open(child_resources.wake_fd.as_raw_fd())?;
    assert_eq!(fd_size(resources.shmem_fd())?, 4096);
    assert_ne!(
        fd_seals(resources.shmem_fd())? & libc::F_SEAL_SHRINK,
        0,
        "spawned shared-memory memfd must be sealed against shrink"
    );
    assert_ne!(
        resources.control_socket_fd(),
        child_resources.control_socket.as_raw_fd()
    );
    assert_ne!(resources.shmem_fd(), child_resources.shmem_fd.as_raw_fd());
    assert_ne!(resources.wake_fd(), child_resources.wake_fd.as_raw_fd());

    Ok(())
}

#[test]
fn qemu_spawn_rejects_empty_region() {
    assert!(matches!(
        create_spawn_resources(0),
        Err(QemuSpawnError::RegionLengthZero)
    ));
}

#[test]
fn qemu_spawn_maps_fixed_child_fds_after_pre_exec() -> Result<(), Box<dyn Error>> {
    if env::var_os(PROBE_ENV).is_some() {
        child_probe_fixed_fds()?;
        return Ok(());
    }

    let (_host, child_resources) = create_spawn_resources(4096)?;
    let source_fds = format!(
        "{},{},{}",
        child_resources.control_socket.as_raw_fd(),
        child_resources.shmem_fd.as_raw_fd(),
        child_resources.wake_fd.as_raw_fd()
    );
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();
    let args = vec![
        String::from("--exact"),
        String::from("spawn::tests::qemu_spawn_maps_fixed_child_fds_after_pre_exec"),
    ];
    let mut child = spawn_process_with_resources(
        &current_exe,
        &args,
        None,
        child_resources,
        &[(PROBE_ENV, "1"), (SOURCE_FDS_ENV, &source_fds)],
        "spawn child fd probe",
    )?;

    let status = child.wait()?;

    assert!(status.success());
    Ok(())
}

#[test]
fn qemu_spawn_run_directory_sets_child_cwd() -> Result<(), Box<dyn Error>> {
    if let Some(expected) = env::var_os(CWD_PROBE_ENV) {
        child_probe_cwd(Path::new(&expected))?;
        return Ok(());
    }

    let (_host, child_resources) = create_spawn_resources(4096)?;
    let source_fds = format!(
        "{},{},{}",
        child_resources.control_socket.as_raw_fd(),
        child_resources.shmem_fd.as_raw_fd(),
        child_resources.wake_fd.as_raw_fd()
    );
    let run_directory = unique_temp_run_directory("qemu-spawn-cwd")?;
    let expected_directory = run_directory.canonicalize()?;
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();
    let args = vec![
        String::from("--exact"),
        String::from("spawn::tests::qemu_spawn_run_directory_sets_child_cwd"),
    ];
    let mut child = spawn_process_with_resources(
        &current_exe,
        &args,
        Some(&run_directory),
        child_resources,
        &[
            (
                CWD_PROBE_ENV,
                expected_directory.as_os_str().to_string_lossy().as_ref(),
            ),
            (SOURCE_FDS_ENV, &source_fds),
        ],
        "spawn child cwd probe",
    )?;

    let status = child.wait()?;

    assert!(status.success());
    std::fs::remove_dir_all(run_directory)?;
    Ok(())
}

#[test]
fn qemu_spawn_clears_inherited_environment_and_preserves_explicit_values()
-> Result<(), Box<dyn Error>> {
    if env::var_os(ENV_CLEAR_CHILD_PROBE).is_some() {
        assert!(env::var_os(INHERITED_ENV_SENTINEL).is_none());
        assert!(env::var_os(ENV_CLEAR_PARENT_PROBE).is_none());
        assert_eq!(env::var(EXPLICIT_ENV_SENTINEL)?, "explicit-child-value");
        child_probe_fixed_fds()?;
        return Ok(());
    }
    if env::var_os(ENV_CLEAR_PARENT_PROBE).is_some() {
        assert_eq!(env::var(INHERITED_ENV_SENTINEL)?, "parent-only-value");
        let (_host, child_resources) = create_spawn_resources(4096)?;
        let source_fds = format!(
            "{},{},{}",
            child_resources.control_socket.as_raw_fd(),
            child_resources.shmem_fd.as_raw_fd(),
            child_resources.wake_fd.as_raw_fd()
        );
        let current_exe = env::current_exe()?;
        let current_exe = current_exe.to_string_lossy().into_owned();
        let args = vec![
            String::from("--exact"),
            String::from(
                "spawn::tests::qemu_spawn_clears_inherited_environment_and_preserves_explicit_values",
            ),
        ];
        let mut child = spawn_process_with_resources(
            &current_exe,
            &args,
            None,
            child_resources,
            &[
                (ENV_CLEAR_CHILD_PROBE, "1"),
                (EXPLICIT_ENV_SENTINEL, "explicit-child-value"),
                (SOURCE_FDS_ENV, &source_fds),
            ],
            "spawn child clean-environment probe",
        )?;

        assert!(child.wait()?.success());
        return Ok(());
    }

    let current_exe = env::current_exe()?;
    let mut parent = Command::new(current_exe)
        .args([
            "--exact",
            "spawn::tests::qemu_spawn_clears_inherited_environment_and_preserves_explicit_values",
        ])
        .env(ENV_CLEAR_PARENT_PROBE, "1")
        .env(INHERITED_ENV_SENTINEL, "parent-only-value")
        .spawn()?;

    assert!(parent.wait()?.success());
    Ok(())
}

#[test]
fn qemu_spawn_kills_child_when_parent_exits() -> Result<(), Box<dyn Error>> {
    if env::var_os(PDEATH_CHILD_ENV).is_some() {
        std::thread::sleep(Duration::from_secs(60));
        return Ok(());
    }
    if env::var_os(PDEATH_PARENT_ENV).is_some() {
        parent_probe_spawn_pdeath_child()?;
        return Ok(());
    }

    let current_exe = env::current_exe()?;
    let output = Command::new(current_exe)
        .args([
            "--exact",
            "spawn::tests::qemu_spawn_kills_child_when_parent_exits",
            "--nocapture",
        ])
        .env(PDEATH_PARENT_ENV, "1")
        .stdout(Stdio::piped())
        .spawn()?
        .wait_with_output()?;

    assert!(output.status.success());
    let pid = parse_pdeath_child_pid(&output.stdout)?;
    assert_process_eventually_gone(pid, Duration::from_secs(2))?;
    Ok(())
}

#[test]
fn qemu_node_child_drop_kills_and_reaps_unreaped_child() -> Result<(), Box<dyn Error>> {
    if env::var_os("CRUCIBLE_QEMU_SPAWN_SLEEP_PROBE").is_some() {
        std::thread::sleep(std::time::Duration::from_secs(60));
        return Ok(());
    }

    let current_exe = env::current_exe()?;
    let child = Command::new(current_exe)
        .args([
            "--exact",
            "spawn::tests::qemu_node_child_drop_kills_and_reaps_unreaped_child",
        ])
        .env("CRUCIBLE_QEMU_SPAWN_SLEEP_PROBE", "1")
        .spawn()?;
    let pid = child.id();
    drop(QemuNodeChild::new(child));

    assert_process_is_gone(pid)?;
    Ok(())
}

fn parent_probe_spawn_pdeath_child() -> Result<(), Box<dyn Error>> {
    let (_host, child_resources) = create_spawn_resources(4096)?;
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();
    let args = vec![
        String::from("--exact"),
        String::from("spawn::tests::qemu_spawn_kills_child_when_parent_exits"),
    ];
    let child = spawn_process_with_resources(
        &current_exe,
        &args,
        None,
        child_resources,
        &[(PDEATH_CHILD_ENV, "1")],
        "spawn parent-death probe child",
    )?;

    println!("{PDEATH_CHILD_PID_PREFIX}{}", child.id());
    let mut stdout = std::io::stdout();
    stdout.flush()?;
    Ok(())
}

fn child_probe_fixed_fds() -> Result<(), Box<dyn Error>> {
    assert_fd_open(QEMU_PLUGIN_CONTROL_FD)?;
    assert_fd_open(QEMU_PLUGIN_SHMEM_FD)?;
    assert_fd_open(QEMU_PLUGIN_WAKE_FD)?;
    assert_eq!(fd_size(QEMU_PLUGIN_SHMEM_FD)?, 4096);
    for fd in source_fds_from_env()? {
        assert_fd_closed(fd)?;
    }
    Ok(())
}

fn child_probe_cwd(expected: &Path) -> Result<(), Box<dyn Error>> {
    let actual = std::env::current_dir()?.canonicalize()?;
    assert_eq!(actual, expected);
    child_probe_fixed_fds()
}

fn unique_temp_run_directory(prefix: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));
    std::fs::create_dir(&path)?;
    Ok(path)
}

fn unique_temp_suffix() -> u64 {
    TEMP_DIR_SUFFIX.fetch_add(1, Ordering::Relaxed)
}

fn assert_fd_open(fd: RawFd) -> Result<(), Box<dyn Error>> {
    let result = unsafe {
        // SAFETY: `fcntl` validates the descriptor number.
        libc::fcntl(fd, libc::F_GETFD)
    };
    if result < 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    Ok(())
}

fn assert_fd_closed(fd: RawFd) -> Result<(), Box<dyn Error>> {
    let result = unsafe {
        // SAFETY: `fcntl` validates the descriptor number.
        libc::fcntl(fd, libc::F_GETFD)
    };
    if result >= 0 {
        return Err(format!("source fd {fd} survived exec").into());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::EBADF) {
        Ok(())
    } else {
        Err(Box::new(error))
    }
}

fn parse_pdeath_child_pid(stdout: &[u8]) -> Result<u32, Box<dyn Error>> {
    let text = String::from_utf8(stdout.to_vec())?;
    for line in text.lines() {
        if let Some(pid) = line.strip_prefix(PDEATH_CHILD_PID_PREFIX) {
            return Ok(pid.parse()?);
        }
    }
    Err(format!("parent-death child pid marker missing in output: {text}").into())
}

// crucible-lint: allow clippy-disallowed-method -- test polling observes OS process cleanup only.
#[allow(clippy::disallowed_methods)]
fn assert_process_eventually_gone(pid: u32, timeout: Duration) -> Result<(), Box<dyn Error>> {
    // Test-only host wait: this polls for OS process cleanup and never
    // feeds Crucible scenario state, scheduling, or fingerprint material.
    let deadline = Instant::now() + timeout;
    loop {
        match assert_process_is_gone(pid) {
            Ok(()) => return Ok(()),
            Err(error) if Instant::now() < deadline => {
                drop(error);
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn fd_size(fd: RawFd) -> Result<i64, Box<dyn Error>> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        // SAFETY: `stat` points to writable storage for `fstat`.
        libc::fstat(fd, stat.as_mut_ptr())
    };
    if result != 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    let stat = unsafe {
        // SAFETY: successful `fstat` initialized `stat`.
        stat.assume_init()
    };
    Ok(stat.st_size)
}

fn fd_seals(fd: RawFd) -> Result<i32, Box<dyn Error>> {
    let seals = unsafe {
        // SAFETY: `fcntl(F_GET_SEALS)` reads metadata from the live test fd.
        libc::fcntl(fd, libc::F_GET_SEALS)
    };
    if seals < 0 {
        return Err(Box::new(io::Error::last_os_error()));
    }
    Ok(seals)
}

fn assert_process_is_gone(pid: u32) -> Result<(), Box<dyn Error>> {
    let pid = libc::pid_t::try_from(pid)?;
    let result = unsafe {
        // SAFETY: `kill(pid, 0)` only probes process existence.
        libc::kill(pid, 0)
    };
    if result == 0 {
        return Err("child process still exists after QemuNodeChild drop".into());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(Box::new(error))
    }
}

fn source_fds_from_env() -> Result<Vec<RawFd>, Box<dyn Error>> {
    let raw = env::var(SOURCE_FDS_ENV)?;
    raw.split(',')
        .map(|part| part.parse::<RawFd>().map_err(Into::into))
        .collect()
}
