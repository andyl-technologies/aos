//! Tests extracted from the adjacent production module.

use std::env;
use std::error::Error;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crucible::ContentHash;

use crate::launch::{
    MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_BYTES, MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_LINES,
    MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES, MAXIMUM_RUNTIME_DETERMINISM_TRACE_LINES,
};

use super::*;

const PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_CHILD_PROBE";
const SOURCE_FDS_ENV: &str = "CRUCIBLE_QEMU_SPAWN_SOURCE_FDS";
const PINNED_CWD_PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PINNED_CWD_PROBE";
const PINNED_BLOCK_PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PINNED_BLOCK_PROBE";
const PDEATH_PARENT_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_PARENT_PROBE";
const PDEATH_CHILD_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PROBE";
const PDEATH_CHILD_PID_PREFIX: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PID=";
const ENV_CLEAR_PARENT_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_PARENT_PROBE";
const ENV_CLEAR_CHILD_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_CHILD_PROBE";
const INHERITED_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_INHERITED_SENTINEL";
const EXPLICIT_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_EXPLICIT_SENTINEL";
const DESCENDANT_SUPERVISOR_ENV: &str = "CRUCIBLE_QEMU_DESCENDANT_SUPERVISOR";
const GUARDED_PROBE_CHILD_MARKER: &str = "guarded-probe-child";
const GUARDED_PROBE_DESCENDANT_PID: &str = "guarded-probe-descendant.pid";
static TEMP_DIR_SUFFIX: AtomicU64 = AtomicU64::new(0);

struct TraceRetentionFixture {
    directory: tempfile::TempDir,
    prepared: QemuPreparedRunDirectory,
}

impl TraceRetentionFixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
        let mut prepared = open_prepared_run_directory_for_test(directory.path())?;
        prepared.child_credentials = Some(QemuChildCredentials {
            user_id: rustix::process::geteuid().as_raw(),
            group_id: rustix::process::getegid().as_raw(),
        });

        Ok(Self {
            directory,
            prepared,
        })
    }

    fn trace_path(&self) -> std::path::PathBuf {
        self.directory
            .path()
            .join(crate::QEMU_RR_CONTROL_BOUNDARY_TRACE_FILE_NAME)
    }

    fn runtime_trace_path(&self) -> std::path::PathBuf {
        self.directory
            .path()
            .join(crate::QEMU_RUNTIME_DETERMINISM_TRACE_FILE_NAME)
    }
}

fn write_sparse_trace(path: &std::path::Path, bytes: u64) -> Result<(), Box<dyn Error>> {
    let mut trace = std::fs::OpenOptions::new().write(true).open(path)?;
    trace.set_len(bytes)?;
    trace.seek(SeekFrom::Start(bytes - 1))?;
    trace.write_all(b"\n")?;
    Ok(())
}

#[test]
fn retained_control_boundary_trace_accepts_only_the_prepared_inode() -> Result<(), Box<dyn Error>> {
    let fixture = TraceRetentionFixture::new()?;
    fixture.prepared.prepare_rr_control_boundary_trace()?;
    std::fs::write(fixture.trace_path(), b"phase=request request=1\n")?;
    assert_eq!(
        fixture
            .prepared
            .retain_rr_control_boundary_trace_after_reap()?,
        "phase=request request=1\n"
    );

    std::fs::remove_file(fixture.trace_path())?;
    std::fs::write(fixture.trace_path(), b"phase=request request=2\n")?;
    std::fs::set_permissions(fixture.trace_path(), std::fs::Permissions::from_mode(0o600))?;
    assert!(matches!(
        fixture
            .prepared
            .retain_rr_control_boundary_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceChanged { .. })
    ));
    Ok(())
}

#[test]
fn retained_runtime_trace_accepts_only_its_prepared_inode() -> Result<(), Box<dyn Error>> {
    let trace = "crucible_sim_determinism_timer seq=1 timer=3 list=1 scope=global owner=rr expire_ps=10 current_ps=10 raw=80\n";
    let fixture = TraceRetentionFixture::new()?;
    fixture.prepared.prepare_runtime_determinism_trace()?;
    std::fs::write(fixture.runtime_trace_path(), trace)?;
    let retained = fixture
        .prepared
        .retain_runtime_determinism_trace_after_reap()?;
    assert_eq!(retained, trace);
    assert_eq!(
        crate::parse_qemu_runtime_determinism_trace(&retained)?.len(),
        1
    );

    let replaced_trace = fixture.runtime_trace_path().with_extension("retained");
    std::fs::rename(fixture.runtime_trace_path(), replaced_trace)?;
    std::fs::write(fixture.runtime_trace_path(), b"replacement\n")?;
    std::fs::set_permissions(
        fixture.runtime_trace_path(),
        std::fs::Permissions::from_mode(0o600),
    )?;
    assert!(matches!(
        fixture
            .prepared
            .retain_runtime_determinism_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceChanged { .. })
    ));
    Ok(())
}

#[test]
fn retained_runtime_liveness_tail_bounds_an_oversized_authenticated_trace()
-> Result<(), Box<dyn Error>> {
    let fixture = TraceRetentionFixture::new()?;
    fixture.prepared.prepare_runtime_determinism_trace()?;
    let trace = (0..2_000)
        .map(|index| {
            format!("crucible_sim_main_loop_poll_ready generation={index} result=1 timeout_ns=-1\n")
        })
        .collect::<String>();
    std::fs::write(fixture.runtime_trace_path(), &trace)?;

    let retained = fixture
        .prepared
        .retain_runtime_liveness_trace_tail_after_reap()?;
    assert!(retained.starts_with(&format!(
        "trace_original_bytes={} trace_tail_truncated=true\n",
        trace.len()
    )));
    assert_eq!(retained.lines().count(), 513);
    assert!(!retained.contains("generation=0 result"));
    assert!(retained.contains("generation=1999 result"));

    let replaced_trace = fixture.runtime_trace_path().with_extension("tail-retained");
    std::fs::rename(fixture.runtime_trace_path(), replaced_trace)?;
    std::fs::write(fixture.runtime_trace_path(), b"replacement\n")?;
    std::fs::set_permissions(
        fixture.runtime_trace_path(),
        std::fs::Permissions::from_mode(0o600),
    )?;
    assert!(matches!(
        fixture
            .prepared
            .retain_runtime_liveness_trace_tail_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceChanged { .. })
    ));

    Ok(())
}

#[test]
fn retained_control_boundary_trace_rejects_unprepared_and_invalid_filesystem_state()
-> Result<(), Box<dyn Error>> {
    let unprepared = TraceRetentionFixture::new()?;
    assert!(
        unprepared
            .prepared
            .retain_rr_control_boundary_trace_after_reap()
            .is_err()
    );

    let empty = TraceRetentionFixture::new()?;
    empty.prepared.prepare_rr_control_boundary_trace()?;
    assert!(matches!(
        empty.prepared.retain_rr_control_boundary_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceLength { actual: 0, .. })
    ));

    let linked = TraceRetentionFixture::new()?;
    linked.prepared.prepare_rr_control_boundary_trace()?;
    std::fs::write(linked.trace_path(), b"line\n")?;
    std::fs::hard_link(
        linked.trace_path(),
        linked.directory.path().join("second-link"),
    )?;
    assert!(matches!(
        linked
            .prepared
            .retain_rr_control_boundary_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceMetadata { links: 2, .. })
    ));

    let wrong_mode = TraceRetentionFixture::new()?;
    wrong_mode.prepared.prepare_rr_control_boundary_trace()?;
    std::fs::write(wrong_mode.trace_path(), b"line\n")?;
    std::fs::set_permissions(
        wrong_mode.trace_path(),
        std::fs::Permissions::from_mode(0o644),
    )?;
    assert!(matches!(
        wrong_mode
            .prepared
            .retain_rr_control_boundary_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceMetadata { mode: 0o644, .. })
    ));

    let symlinked = TraceRetentionFixture::new()?;
    symlinked.prepared.prepare_rr_control_boundary_trace()?;
    std::fs::remove_file(symlinked.trace_path())?;
    let target = symlinked.directory.path().join("trace-target");
    std::fs::write(&target, b"line\n")?;
    symlink(&target, symlinked.trace_path())?;
    assert!(
        symlinked
            .prepared
            .retain_rr_control_boundary_trace_after_reap()
            .is_err()
    );
    Ok(())
}

#[test]
fn retained_control_boundary_trace_enforces_content_and_aggregate_bounds()
-> Result<(), Box<dyn Error>> {
    let oversized = TraceRetentionFixture::new()?;
    oversized.prepared.prepare_rr_control_boundary_trace()?;
    std::fs::write(
        oversized.trace_path(),
        vec![b'x'; usize::try_from(MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_BYTES)? + 1],
    )?;
    assert!(matches!(
        oversized
            .prepared
            .retain_rr_control_boundary_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceLength { .. })
    ));

    let runtime_above_prior_limit = TraceRetentionFixture::new()?;
    runtime_above_prior_limit
        .prepared
        .prepare_runtime_determinism_trace()?;
    let runtime_bytes = MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES / 2 + 1;
    write_sparse_trace(
        &runtime_above_prior_limit.runtime_trace_path(),
        runtime_bytes,
    )?;
    assert_eq!(
        runtime_above_prior_limit
            .prepared
            .retain_runtime_determinism_trace_after_reap()?
            .len(),
        usize::try_from(runtime_bytes)?
    );

    let runtime_oversized = TraceRetentionFixture::new()?;
    runtime_oversized
        .prepared
        .prepare_runtime_determinism_trace()?;
    write_sparse_trace(
        &runtime_oversized.runtime_trace_path(),
        MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES + 1,
    )?;
    assert!(matches!(
        runtime_oversized
            .prepared
            .retain_runtime_determinism_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceLength { .. })
    ));

    let too_many_lines = TraceRetentionFixture::new()?;
    too_many_lines
        .prepared
        .prepare_rr_control_boundary_trace()?;
    std::fs::write(
        too_many_lines.trace_path(),
        vec![b'\n'; MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_LINES + 1],
    )?;
    assert!(matches!(
        too_many_lines
            .prepared
            .retain_rr_control_boundary_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceLines {
            actual,
            maximum: MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_LINES,
            ..
        }) if actual == MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_LINES + 1
    ));

    let runtime_above_rr_line_limit = TraceRetentionFixture::new()?;
    runtime_above_rr_line_limit
        .prepared
        .prepare_runtime_determinism_trace()?;
    let runtime_lines = vec![b'\n'; MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_LINES + 1];
    std::fs::write(
        runtime_above_rr_line_limit.runtime_trace_path(),
        &runtime_lines,
    )?;
    assert_eq!(
        runtime_above_rr_line_limit
            .prepared
            .retain_runtime_determinism_trace_after_reap()?
            .len(),
        runtime_lines.len()
    );

    let runtime_too_many_lines = TraceRetentionFixture::new()?;
    runtime_too_many_lines
        .prepared
        .prepare_runtime_determinism_trace()?;
    std::fs::write(
        runtime_too_many_lines.runtime_trace_path(),
        vec![b'\n'; MAXIMUM_RUNTIME_DETERMINISM_TRACE_LINES + 1],
    )?;
    assert!(matches!(
        runtime_too_many_lines
            .prepared
            .retain_runtime_determinism_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceLines {
            actual,
            maximum: MAXIMUM_RUNTIME_DETERMINISM_TRACE_LINES,
            ..
        }) if actual == MAXIMUM_RUNTIME_DETERMINISM_TRACE_LINES + 1
    ));

    let mut outside_admission = TraceRetentionFixture::new()?;
    outside_admission
        .prepared
        .prepare_rr_control_boundary_trace()?;
    std::fs::write(outside_admission.trace_path(), b"line\n")?;
    outside_admission.prepared.admitted_ceiling.2 = 1;
    assert!(matches!(
        outside_admission
            .prepared
            .retain_rr_control_boundary_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceExceedsAdmission { .. })
    ));

    let mut runtime_outside_admission = TraceRetentionFixture::new()?;
    runtime_outside_admission
        .prepared
        .prepare_runtime_determinism_trace()?;
    std::fs::write(
        runtime_outside_admission.runtime_trace_path(),
        b"runtime-row\n",
    )?;
    runtime_outside_admission.prepared.admitted_ceiling.2 = 1;
    assert!(matches!(
        runtime_outside_admission
            .prepared
            .retain_runtime_determinism_trace_after_reap(),
        Err(QemuSpawnError::DiagnosticTraceExceedsAdmission { .. })
    ));
    Ok(())
}

fn spawn_unpinned_test_process_with_resources(
    executable: &str,
    args: &[String],
    child_resources: QemuSpawnChildResources,
    envs: &[(&str, &str)],
    operation: &'static str,
    process_contract: Option<&QemuChildProcessContract>,
) -> Result<std::process::Child, QemuSpawnError> {
    let control_fd = child_resources.control_socket.as_raw_fd();
    let shmem_fd = child_resources.shmem_fd.as_raw_fd();
    let wake_fd = child_resources.wake_fd.as_raw_fd();
    let expected_parent_pid = unsafe {
        // SAFETY: `getpid` has no preconditions.
        libc::getpid()
    };
    let process_contract = process_contract.map(|contract| ChildProcessContractRaw {
        cgroup_procs: contract.cgroup_procs.as_raw_fd(),
        cancellation_event: contract.cancellation_event.as_raw_fd(),
        maximum_file_bytes: contract.maximum_writable_bytes,
        credentials: contract.credentials,
    });

    let mut command = Command::new(executable);
    command
        .env_clear()
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    for (key, value) in envs {
        command.env(key, value);
    }

    // SAFETY: this test-only unpinned launcher exercises the descriptor and
    // containment setup without a run-directory fixture. Its closure has the
    // same async-signal-safe syscall boundary as the pinned production path.
    unsafe {
        command.pre_exec(move || {
            if let Some(contract) = process_contract {
                install_attempt_process_contract(contract)?;
            }
            if let Some(credentials) = process_contract.and_then(|contract| contract.credentials) {
                install_child_credentials(credentials)?;
            }
            install_child_process_contract(control_fd, shmem_fd, wake_fd, expected_parent_pid)
        });
    }

    command
        .spawn()
        .map_err(|source| QemuSpawnError::Io { operation, source })
}

fn pipe_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    let status = unsafe {
        // SAFETY: `descriptors` provides two writable descriptor slots.
        libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC)
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    let read = unsafe {
        // SAFETY: successful pipe2 returned a uniquely owned read descriptor.
        OwnedFd::from_raw_fd(descriptors[0])
    };
    let write = unsafe {
        // SAFETY: successful pipe2 returned a uniquely owned write descriptor.
        OwnedFd::from_raw_fd(descriptors[1])
    };
    Ok((read, write))
}

fn event_fd_for_test() -> io::Result<OwnedFd> {
    event_fd_with_flags(libc::EFD_CLOEXEC | libc::EFD_NONBLOCK)
}

fn event_fd_with_flags(flags: i32) -> io::Result<OwnedFd> {
    let descriptor = unsafe {
        // SAFETY: eventfd has no pointer arguments and returns one new fd.
        libc::eventfd(0, flags)
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        // SAFETY: successful eventfd returned a uniquely owned descriptor.
        OwnedFd::from_raw_fd(descriptor)
    })
}

fn write_eventfd(descriptor: RawFd, value: u64) -> io::Result<()> {
    let written = unsafe {
        // SAFETY: `value` is a valid u64 input buffer for eventfd.
        libc::write(
            descriptor,
            (&value as *const u64).cast(),
            std::mem::size_of::<u64>(),
        )
    };
    if written == 8 {
        Ok(())
    } else if written < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::from_raw_os_error(libc::EIO))
    }
}

fn current_file_size_limit() -> io::Result<u64> {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    let status = unsafe {
        // SAFETY: `limit` points to writable storage for one rlimit value.
        libc::getrlimit(libc::RLIMIT_FSIZE, limit.as_mut_ptr())
    };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        // SAFETY: successful getrlimit initialized the complete value.
        limit.assume_init().rlim_cur
    })
}

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
fn guarded_pre_exec_places_child_before_exec() -> Result<(), Box<dyn Error>> {
    if env::var_os(PROBE_ENV).is_some() {
        let no_new_privileges = unsafe {
            // SAFETY: PR_GET_NO_NEW_PRIVS reads one scalar process attribute.
            libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
        };
        assert_eq!(no_new_privileges, 1);
        return Ok(());
    }
    let (cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let contract =
        QemuChildProcessContract::for_test(cgroup_write, cancellation, current_file_size_limit()?);
    let (_host, child_resources) = create_spawn_resources(4096)?;
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();
    let args = vec![
        String::from("--exact"),
        String::from("spawn::tests::guarded_pre_exec_places_child_before_exec"),
    ];

    let mut child = spawn_unpinned_test_process_with_resources(
        &current_exe,
        &args,
        child_resources,
        &[(PROBE_ENV, "1")],
        "spawn guarded pre-exec probe",
        Some(&contract),
    )?;
    assert!(child.wait()?.success());

    let mut placement = [0_u8; 2];
    std::fs::File::from(cgroup_read).read_exact(&mut placement)?;
    assert_eq!(&placement, CGROUP_ATTACH_SELF);
    Ok(())
}

#[test]
fn guarded_image_helper_uses_the_attempt_contract_and_pinned_directory()
-> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let (cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let contract =
        QemuChildProcessContract::for_test(cgroup_write, cancellation, current_file_size_limit()?);
    let directory = tempfile::tempdir()?;
    std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        directory.path(),
        &contract,
    )?;
    let executable = env::current_exe()?;
    let args = [
        std::ffi::OsString::from("--exact"),
        std::ffi::OsString::from("spawn::tests::pre_exec_vmstate_name_matches_the_launch_contract"),
    ];

    run_guarded_image_tool(
        &executable,
        &args,
        "run contained image-tool probe",
        &prepared,
        &contract,
    )?;

    let mut placement = [0_u8; 2];
    std::fs::File::from(cgroup_read).read_exact(&mut placement)?;
    assert_eq!(&placement, CGROUP_ATTACH_SELF);
    Ok(())
}

#[test]
fn guarded_image_helper_observes_sticky_cancellation_before_exec() -> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let (cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    write_eventfd(cancellation.as_raw_fd(), 1)?;
    let contract =
        QemuChildProcessContract::for_test(cgroup_write, cancellation, current_file_size_limit()?);
    let directory = tempfile::tempdir()?;
    std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        directory.path(),
        &contract,
    )?;
    let executable = env::current_exe()?;

    for _ in 0..2 {
        let error = match run_guarded_image_tool(
            &executable,
            &[],
            "run canceled image-tool probe",
            &prepared,
            &contract,
        ) {
            Err(error) => error,
            Ok(()) => panic!("sticky cancellation must reject every helper before exec"),
        };
        assert!(error.child.is_none());
        assert!(matches!(
            error.source,
            QemuSpawnError::Io { source, .. }
                if source.raw_os_error() == Some(libc::ECANCELED)
        ));
    }

    let mut placements = [0_u8; 4];
    std::fs::File::from(cgroup_read).read_exact(&mut placements)?;
    assert_eq!(&placements, b"0\n0\n");
    Ok(())
}

#[test]
fn guarded_probe_times_out_and_reaps_a_live_child() -> Result<(), Box<dyn Error>> {
    let fixture = GuardedProbeFixture::new(
        "spawn::tests::guarded_probe_timeout_child",
        ProbeChildDirectoryAccess::ReadOnly,
    )?;
    let error = fixture.run(1024, Duration::from_millis(100))?;

    assert!(matches!(
        error.source,
        QemuSpawnError::GuardedQemuProbeTimeout
    ));
    assert!(error.child.is_none());
    Ok(())
}

#[test]
fn guarded_probe_bounds_a_flooding_output_stream() -> Result<(), Box<dyn Error>> {
    let fixture = GuardedProbeFixture::new(
        "spawn::tests::guarded_probe_flood_child",
        ProbeChildDirectoryAccess::ReadOnly,
    )?;
    let error = fixture.run(1024, Duration::from_secs(2))?;

    assert!(matches!(
        error.source,
        QemuSpawnError::GuardedQemuProbeOutputLimit {
            maximum_bytes: 1024
        }
    ));
    assert!(error.child.is_none());
    Ok(())
}

#[test]
fn guarded_probe_deadline_survives_descendant_held_output_pipes() -> Result<(), Box<dyn Error>> {
    if env::var_os(DESCENDANT_SUPERVISOR_ENV).is_none() {
        let current_executable = env::current_exe()?;
        let output = Command::new(current_executable)
            .arg("--exact")
            .arg("spawn::tests::guarded_probe_deadline_survives_descendant_held_output_pipes")
            .env(DESCENDANT_SUPERVISOR_ENV, "1")
            .output()?;
        assert!(
            output.status.success(),
            "descendant supervisor failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(());
    }

    // The exact-test subprocess is dedicated to this regression, so adopting
    // its orphaned helper cannot capture unrelated children.
    rustix::process::set_child_subreaper(Some(rustix::process::Pid::INIT))?;
    let fixture = GuardedProbeFixture::new(
        "spawn::tests::guarded_probe_descendant_launcher_child",
        ProbeChildDirectoryAccess::WritablePidFile,
    )?;
    let error = fixture.run(1024, Duration::from_millis(100))?;
    let descendant_pid = fixture.descendant_pid()?;
    let descendant = AdoptedDescendant::new(descendant_pid);

    assert!(matches!(
        error.source,
        QemuSpawnError::GuardedQemuProbeTimeout
    ));
    assert!(error.child.is_none());
    descendant.terminate_and_reap()?;
    Ok(())
}

#[test]
fn guarded_probe_timeout_child() -> Result<(), Box<dyn Error>> {
    if probe_child_is_active() {
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

#[test]
fn guarded_probe_flood_child() -> Result<(), Box<dyn Error>> {
    if probe_child_is_active() {
        io::stdout().write_all(&[b'x'; 4096])?;
    }
    Ok(())
}

#[test]
fn guarded_probe_descendant_launcher_child() -> Result<(), Box<dyn Error>> {
    if !probe_child_is_active() {
        return Ok(());
    }

    let descendant = Command::new(env::current_exe()?)
        .arg("--exact")
        .arg("spawn::tests::guarded_probe_descendant_pipe_holder_child")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    std::fs::write(GUARDED_PROBE_DESCENDANT_PID, descendant.id().to_string())?;
    Ok(())
}

#[test]
fn guarded_probe_descendant_pipe_holder_child() -> Result<(), Box<dyn Error>> {
    if probe_child_is_active() {
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

fn probe_child_is_active() -> bool {
    Path::new(GUARDED_PROBE_CHILD_MARKER).is_file()
}

#[test]
fn canceled_pre_exec_contract_stays_canceled_across_spawns() -> Result<(), Box<dyn Error>> {
    let (cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    write_eventfd(cancellation.as_raw_fd(), 1)?;
    let contract =
        QemuChildProcessContract::for_test(cgroup_write, cancellation, current_file_size_limit()?);
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();

    for _ in 0..2 {
        let (_host, child_resources) = create_spawn_resources(4096)?;
        let error = match spawn_unpinned_test_process_with_resources(
            &current_exe,
            &[],
            child_resources,
            &[],
            "spawn canceled pre-exec probe",
            Some(&contract),
        ) {
            Err(error) => error,
            Ok(_) => panic!("cancellation must reject every child before exec"),
        };
        assert!(matches!(
            error,
            QemuSpawnError::Io { source, .. }
                if source.raw_os_error() == Some(libc::ECANCELED)
        ));
    }

    let mut placements = [0_u8; 4];
    std::fs::File::from(cgroup_read).read_exact(&mut placements)?;
    assert_eq!(&placements, b"0\n0\n");
    Ok(())
}

#[test]
fn process_contract_rejects_forged_regular_descriptors() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempfile()?;
    let duplicate = duplicate_cloexec_fd(temporary.as_raw_fd(), "duplicate forged contract fd")?;
    let second_duplicate =
        duplicate_cloexec_fd(temporary.as_raw_fd(), "duplicate forged contract directory")?;
    let credentials = valid_distinct_credentials()?;
    let error = match QemuChildProcessContract::new(
        second_duplicate,
        temporary.into(),
        duplicate,
        crate::linux_cgroup::LinuxQemuCgroupLimits::new(1, 4096, 1)?,
        4096,
        credentials,
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("regular files must not construct a containment contract"),
    };
    assert!(matches!(error, QemuSpawnError::Io { .. }));
    Ok(())
}

#[test]
fn exact_checkpoint_root_is_immutable_across_contract_generations() -> Result<(), Box<dyn Error>> {
    let root_a = ContentHash { bytes: [0x11; 32] };
    let root_b = ContentHash { bytes: [0x22; 32] };

    let (_, fresh_cgroup) = pipe_pair()?;
    let fresh = QemuChildProcessContract::for_test(
        fresh_cgroup,
        event_fd_for_test()?,
        current_file_size_limit()?,
    );
    assert!(fresh.require_exact_checkpoint_root(root_a).is_err());

    let (_, exact_cgroup) = pipe_pair()?;
    let exact = QemuChildProcessContract::for_exact_checkpoint_test(
        exact_cgroup,
        event_fd_for_test()?,
        current_file_size_limit()?,
        root_a,
    );
    assert!(exact.require_exact_checkpoint_root(root_a).is_ok());
    assert!(exact.require_exact_checkpoint_root(root_b).is_err());

    let cloned = exact.try_clone_for_attempt_generation()?;
    assert!(cloned.require_exact_checkpoint_root(root_a).is_ok());
    assert!(cloned.require_exact_checkpoint_root(root_b).is_err());

    let successor = exact.try_derive_for_exact_checkpoint_root(root_b)?;
    assert!(successor.require_exact_checkpoint_root(root_b).is_ok());
    assert!(successor.require_exact_checkpoint_root(root_a).is_err());
    assert!(exact.require_exact_checkpoint_root(root_a).is_ok());
    let successor_generation = successor.try_clone_for_attempt_generation()?;
    assert!(
        successor_generation
            .require_exact_checkpoint_root(root_b)
            .is_ok()
    );
    Ok(())
}

#[test]
fn guarded_credentials_reject_root_and_supervisor_identity() -> Result<(), Box<dyn Error>> {
    let supervisor = current_supervisor_credentials()?;
    let distinct_user_id = distinct_nonzero_id(&supervisor.user_ids);
    let mut supervisor_groups = supervisor.supplementary_group_ids.clone();
    supervisor_groups.extend(supervisor.group_ids);
    let distinct_group_id = distinct_nonzero_id(&supervisor_groups);

    assert!(QemuChildCredentials::new(0, distinct_group_id).is_err());
    assert!(QemuChildCredentials::new(distinct_user_id, 0).is_err());
    for user_id in supervisor.user_ids {
        assert!(QemuChildCredentials::new(user_id, distinct_group_id).is_err());
    }
    for group_id in supervisor_groups {
        assert!(QemuChildCredentials::new(distinct_user_id, group_id).is_err());
    }
    assert!(QemuChildCredentials::new(distinct_user_id, distinct_group_id).is_ok());
    Ok(())
}

fn valid_distinct_credentials() -> Result<QemuChildCredentials, QemuSpawnError> {
    let supervisor = current_supervisor_credentials()?;
    let mut supervisor_groups = supervisor.supplementary_group_ids;
    supervisor_groups.extend(supervisor.group_ids);
    QemuChildCredentials::new(
        distinct_nonzero_id(&supervisor.user_ids),
        distinct_nonzero_id(&supervisor_groups),
    )
}

fn distinct_nonzero_id(excluded: &[u32]) -> u32 {
    (1..=65_534)
        .rev()
        .find(|candidate| !excluded.contains(candidate))
        .unwrap_or(65_535)
}

#[test]
fn cancellation_contract_rejects_blocking_and_non_event_descriptors() -> Result<(), Box<dyn Error>>
{
    let blocking_event = event_fd_with_flags(libc::EFD_CLOEXEC)?;
    assert!(validate_cancellation_eventfd(blocking_event.as_raw_fd()).is_err());

    let (pipe_read, _pipe_write) = pipe_pair()?;
    assert!(validate_cancellation_eventfd(pipe_read.as_raw_fd()).is_err());
    Ok(())
}

#[test]
fn prepared_vmstate_container_rejects_symlinks() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let target = directory.path().join("outside.qcow2");
    std::fs::File::create(&target)?;
    symlink(
        &target,
        directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME),
    )?;

    let error = match open_prepared_run_directory_for_test(directory.path()) {
        Err(error) => error,
        Ok(_) => panic!("prepared VMState path must not follow a symlink"),
    };
    assert!(error.to_string().contains("VMState"));
    Ok(())
}

#[test]
fn prepared_run_directory_rejects_a_final_symlink() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let actual = root.path().join("actual");
    let linked = root.path().join("linked");
    std::fs::create_dir(&actual)?;
    std::fs::File::create(actual.join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    symlink(&actual, &linked)?;

    assert!(open_prepared_run_directory_for_test(&linked).is_err());
    Ok(())
}

#[test]
fn pre_exec_vmstate_name_matches_the_launch_contract() {
    assert_eq!(
        &VMSTATE_FILE_NAME_C[..VMSTATE_FILE_NAME_C.len() - 1],
        crate::DEFAULT_VMSTATE_FILE_NAME.as_bytes()
    );
    assert_eq!(VMSTATE_FILE_NAME_C.last(), Some(&0));
}

#[test]
fn prepared_run_directory_rejects_vmstate_replacement() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::File::create(&vmstate_path)?;
    let prepared = open_prepared_run_directory_for_test(directory.path())?;

    std::fs::remove_file(&vmstate_path)?;
    std::fs::File::create(&vmstate_path)?;

    assert!(matches!(
        prepared.revalidate(),
        Err(QemuSpawnError::PreparedDeviceStateChanged { .. })
    ));
    Ok(())
}

#[test]
fn prepared_run_directory_rejects_root_overlay_replacement() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let prepared = open_prepared_run_directory_for_test(directory.path())?;
    let overlay_path = directory.path().join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);

    std::fs::remove_file(&overlay_path)?;
    std::fs::File::create(&overlay_path)?;

    assert!(matches!(
        prepared.revalidate(),
        Err(QemuSpawnError::PreparedRootOverlayChanged { .. })
    ));
    Ok(())
}

#[test]
fn direct_launch_pin_rejects_overlay_replacement_after_revalidation() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let prepared = open_prepared_run_directory_for_test(directory.path())?;
    prepared.revalidate()?;

    let overlay_path = directory.path().join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    std::fs::remove_file(&overlay_path)?;
    std::fs::File::create(&overlay_path)?;

    assert!(matches!(
        GuardedLaunchImagePins::new(&prepared),
        Err(QemuSpawnError::PreparedRootOverlayChanged { .. })
    ));
    Ok(())
}

#[test]
fn independent_launch_pin_rejects_vmstate_replacement() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::File::create(&vmstate_path)?;
    let prepared = open_prepared_run_directory_for_test(directory.path())?;
    prepared.revalidate()?;

    std::fs::remove_file(&vmstate_path)?;
    std::fs::File::create(&vmstate_path)?;

    assert!(matches!(
        GuardedLaunchImagePins::new(&prepared),
        Err(QemuSpawnError::PreparedDeviceStateChanged { .. })
    ));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn vmstate_launch_pin_has_independent_ofd_locks() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::File::create(&vmstate_path)?;
    let prepared = open_prepared_run_directory_for_test(directory.path())?;
    let image_pins = GuardedLaunchImagePins::new(&prepared)?;
    let mut lock = libc::flock {
        l_type: libc::F_WRLCK as libc::c_short,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start: 200,
        l_len: 1,
        l_pid: 0,
    };

    let locked = unsafe {
        // SAFETY: both descriptors and the lock structure remain live.
        libc::fcntl(image_pins.vmstate.as_raw_fd(), libc::F_OFD_SETLK, &lock)
    };
    assert_eq!(locked, 0);

    lock.l_type = libc::F_WRLCK as libc::c_short;
    let queried = unsafe {
        // SAFETY: the retained descriptor and writable lock structure are live.
        libc::fcntl(prepared.vmstate.as_raw_fd(), libc::F_OFD_GETLK, &mut lock)
    };
    assert_eq!(queried, 0);
    assert_eq!(lock.l_type, libc::F_WRLCK as libc::c_short);
    Ok(())
}

#[test]
fn pinned_pre_exec_rejects_vmstate_replacement() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::File::create(&vmstate_path)?;
    let prepared = open_prepared_run_directory_for_test(directory.path())?;
    let image_pins = GuardedLaunchImagePins::new(&prepared)?;
    std::fs::remove_file(&vmstate_path)?;
    std::fs::File::create(&vmstate_path)?;

    let (_host, child_resources) = create_spawn_resources(4096)?;
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();
    let error = match spawn_process_with_resources(
        &current_exe,
        &[],
        &prepared,
        child_resources,
        &image_pins,
        &[],
        None,
    ) {
        Err(error) => error,
        Ok(_) => panic!("pre-exec must reject a replaced VMState inode"),
    };

    assert!(matches!(
        error,
        QemuSpawnError::Io { source, .. }
            if source.raw_os_error() == Some(libc::ESTALE)
    ));
    Ok(())
}

#[test]
fn pinned_run_directory_survives_diagnostic_path_replacement() -> Result<(), Box<dyn Error>> {
    if let Some(expected) = env::var_os(PINNED_CWD_PROBE_ENV) {
        child_probe_cwd(Path::new(&expected))?;
        return Ok(());
    }

    let root = tempfile::tempdir()?;
    let diagnostic_path = root.path().join("attempt");
    let retained_path = root.path().join("retained-attempt");
    std::fs::create_dir(&diagnostic_path)?;
    std::fs::File::create(diagnostic_path.join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let prepared = open_prepared_run_directory_for_test(&diagnostic_path)?;
    let image_pins = GuardedLaunchImagePins::new(&prepared)?;

    std::fs::rename(&diagnostic_path, &retained_path)?;
    std::fs::create_dir(&diagnostic_path)?;
    std::fs::File::create(diagnostic_path.join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    prepared.revalidate()?;

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
        String::from("spawn::tests::pinned_run_directory_survives_diagnostic_path_replacement"),
    ];
    let expected = retained_path.canonicalize()?;
    let mut child = spawn_process_with_resources(
        &current_exe,
        &args,
        &prepared,
        child_resources,
        &image_pins,
        &[
            (
                PINNED_CWD_PROBE_ENV,
                expected.as_os_str().to_string_lossy().as_ref(),
            ),
            (SOURCE_FDS_ENV, &source_fds),
        ],
        None,
    )?;

    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn inherited_block_roots_survive_names_replaced_after_exec() -> Result<(), Box<dyn Error>> {
    if let Some(probe_root) = env::var_os(PINNED_BLOCK_PROBE_ENV) {
        let probe_root = Path::new(&probe_root);
        std::fs::write(probe_root.join("ready"), b"ready")?;
        wait_for_probe_file(&probe_root.join("release"))?;

        child_probe_fixed_fds()?;
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{QEMU_VMSTATE_LAUNCH_FD}"))?,
            b"original-vmstate"
        );
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{QEMU_ROOT_OVERLAY_READ_LAUNCH_FD}"))?,
            b"original-overlay"
        );
        assert_eq!(
            std::fs::read(format!("/proc/self/fd/{QEMU_ROOT_OVERLAY_WRITE_LAUNCH_FD}"))?,
            b"original-overlay"
        );
        return Ok(());
    }

    let probe_root = tempfile::tempdir()?;
    let attempt = probe_root.path().join("attempt");
    std::fs::create_dir(&attempt)?;
    let vmstate = attempt.join(crate::DEFAULT_VMSTATE_FILE_NAME);
    let overlay = attempt.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    std::fs::write(&vmstate, b"original-vmstate")?;
    std::fs::write(&overlay, b"original-overlay")?;

    let command = guarded_resource_test_command()?;
    let contract = wide_test_process_contract()?;
    let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        &attempt,
        &contract,
    )?;
    let image_pins = GuardedLaunchImagePins::new(&prepared)?;
    let overlay_pin = image_pins
        .overlay
        .as_ref()
        .ok_or("root overlay pin missing")?;
    let materialization_overlay = prepared
        .root_overlay
        .as_ref()
        .ok_or("materialization overlay pin missing")?;
    let read_flags = unsafe {
        // SAFETY: the launch descriptor is live for this test.
        libc::fcntl(overlay_pin.read.as_raw_fd(), libc::F_GETFL)
    };
    let write_flags = unsafe {
        // SAFETY: the launch descriptor is live for this test.
        libc::fcntl(overlay_pin.write.as_raw_fd(), libc::F_GETFL)
    };
    let materialization_flags = unsafe {
        // SAFETY: the materialization descriptor is live for this test.
        libc::fcntl(materialization_overlay.as_raw_fd(), libc::F_GETFL)
    };
    assert_ne!(read_flags, -1);
    assert_ne!(write_flags, -1);
    assert_ne!(materialization_flags, -1);
    assert_eq!(read_flags & libc::O_ACCMODE, libc::O_RDONLY);
    assert_eq!(write_flags & libc::O_ACCMODE, libc::O_RDWR);
    assert_ne!(read_flags & libc::O_DIRECT, 0);
    assert_ne!(write_flags & libc::O_DIRECT, 0);
    assert_eq!(materialization_flags & libc::O_DIRECT, 0);
    assert!(image_pins.vmstate.as_raw_fd() >= CHILD_SOURCE_FD_MIN);
    assert!(overlay_pin.read.as_raw_fd() >= CHILD_SOURCE_FD_MIN);
    assert!(overlay_pin.write.as_raw_fd() >= CHILD_SOURCE_FD_MIN);

    let (_host, child_resources) = create_spawn_resources(4096)?;
    for source_fd in [
        child_resources.control_socket.as_raw_fd(),
        child_resources.shmem_fd.as_raw_fd(),
        child_resources.wake_fd.as_raw_fd(),
    ] {
        assert!(source_fd >= CHILD_SOURCE_FD_MIN);
    }
    let source_fds = format!(
        "{},{},{},{},{},{}",
        child_resources.control_socket.as_raw_fd(),
        child_resources.shmem_fd.as_raw_fd(),
        child_resources.wake_fd.as_raw_fd(),
        image_pins.vmstate.as_raw_fd(),
        overlay_pin.read.as_raw_fd(),
        overlay_pin.write.as_raw_fd(),
    );
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();
    let probe_path = probe_root
        .path()
        .to_str()
        .ok_or("probe path is not UTF-8")?;
    let args = vec![
        String::from("--exact"),
        String::from("spawn::tests::inherited_block_roots_survive_names_replaced_after_exec"),
    ];
    let mut child = spawn_process_with_resources(
        &current_exe,
        &args,
        &prepared,
        child_resources,
        &image_pins,
        &[
            (PINNED_BLOCK_PROBE_ENV, probe_path),
            (SOURCE_FDS_ENV, &source_fds),
        ],
        None,
    )?;

    wait_for_probe_file(&probe_root.path().join("ready"))?;
    std::fs::rename(&vmstate, attempt.join("old-vmstate"))?;
    std::fs::rename(&overlay, attempt.join("old-overlay"))?;
    std::fs::write(&vmstate, b"forged-vmstate")?;
    std::fs::write(&overlay, b"forged-overlay")?;
    std::fs::write(probe_root.path().join("release"), b"release")?;

    assert!(child.wait()?.success());
    assert_eq!(std::fs::read(&vmstate)?, b"forged-vmstate");
    assert_eq!(std::fs::read(&overlay)?, b"forged-overlay");
    Ok(())
}

#[test]
fn guarded_launch_rewrites_only_authenticated_block_roots() -> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let canonical = command.args();
    let guarded = guarded_launch_args(canonical, true)?;

    assert_eq!(guarded[0], "-add-fd");
    assert_eq!(guarded[2], "-add-fd");
    assert_eq!(guarded[4], "-add-fd");
    assert_eq!(guarded[1], "fd=6,set=1,opaque=crucible-vmstate");
    assert_eq!(guarded[3], "fd=7,set=2,opaque=crucible-root-overlay-read");
    assert_eq!(guarded[5], "fd=8,set=2,opaque=crucible-root-overlay-write");
    assert!(
        guarded
            .iter()
            .any(|arg| arg.contains("file.filename=/dev/fdset/1"))
    );
    assert!(guarded.iter().any(|arg| arg.contains("file=/dev/fdset/2")));
    assert!(!guarded.iter().any(|arg| {
        arg.contains("file.filename=crucible-vmstate.qcow2")
            || arg.contains("file=crucible-root-overlay.qcow2")
    }));

    let vmstate_arg = canonical
        .iter()
        .find(|arg| arg.contains("file.filename=crucible-vmstate.qcow2"))
        .ok_or("canonical VMState argument is missing")?;
    let mut duplicated = canonical.to_vec();
    duplicated.extend(["-blockdev".to_owned(), vmstate_arg.clone()]);
    assert!(guarded_launch_args(&duplicated, true).is_err());
    let missing_vmstate = canonical
        .iter()
        .filter(|arg| *arg != vmstate_arg)
        .cloned()
        .collect::<Vec<_>>();
    assert!(guarded_launch_args(&missing_vmstate, true).is_err());
    Ok(())
}

// crucible-lint: allow clippy-disallowed-method -- test process handoff uses host time only.
#[allow(clippy::disallowed_methods)]
fn wait_for_probe_file(path: &Path) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() {
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for probe file {}", path.display()).into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[test]
fn guarded_preparation_rejects_underprovisioned_launch_before_run_directory_access()
-> Result<(), Box<dyn Error>> {
    let (_cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let contract = QemuChildProcessContract::from_unvalidated_test_descriptors(
        cgroup_write,
        cancellation,
        u32::MAX,
        1,
        u64::MAX,
    );
    let command = guarded_resource_test_command()?;
    let missing_run_directory = std::env::temp_dir().join(format!(
        "crucible-missing-guarded-run-directory-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));

    let error = match QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        &missing_run_directory,
        &contract,
    ) {
        Err(error) => error,
        Ok(_) => panic!("underprovisioned guarded preparation must fail before path access"),
    };

    assert!(matches!(
        error,
        QemuSpawnError::LaunchResources {
            source: crate::QemuLaunchResourceError::ResidentBytes { admitted: 1, .. }
        }
    ));
    assert!(!missing_run_directory.exists());
    Ok(())
}

#[test]
fn materialization_preparation_rejects_before_run_directory_access() -> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let (_cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let contract = QemuChildProcessContract::from_unvalidated_test_descriptors(
        cgroup_write,
        cancellation,
        u32::MAX,
        1,
        u64::MAX,
    );
    let missing_run_directory = std::env::temp_dir().join(format!(
        "crucible-missing-materialization-run-directory-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));

    assert!(matches!(
        QemuPreparedRunDirectory::open_for_test_requirements(
            command.resource_requirements(),
            &missing_run_directory,
            &contract,
        ),
        Err(QemuSpawnError::LaunchResources {
            source: crate::QemuLaunchResourceError::ResidentBytes { admitted: 1, .. }
        })
    ));
    assert!(!missing_run_directory.exists());
    Ok(())
}

#[test]
fn guarded_spawn_rejects_another_attempt_with_identical_limits() -> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let first_contract = wide_test_process_contract()?;
    let second_contract = wide_test_process_contract()?;
    let directory = tempfile::tempdir()?;
    std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        directory.path(),
        &first_contract,
    )?;

    assert!(matches!(
        spawn_prepared_qemu_child_with_fds_in_directory_guarded(
            &command,
            &prepared,
            4096,
            &second_contract,
        ),
        Err(QemuSpawnError::PreparedLaunchAdmissionChanged)
    ));
    Ok(())
}

#[test]
fn prepared_trace_admission_rejects_an_unreserved_command() -> Result<(), Box<dyn Error>> {
    let traced = guarded_resource_test_command_builder()?
        .with_runtime_determinism_trace()
        .build()?;
    let ordinary = guarded_resource_test_command()?;
    let contract = wide_test_process_contract()?;
    let directory = tempfile::tempdir()?;
    std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        traced.resource_requirements(),
        directory.path(),
        &contract,
    )?;

    assert!(prepared.validate_launch_basis(&traced, &contract).is_ok());
    assert!(matches!(
        prepared.validate_launch_basis(&ordinary, &contract),
        Err(QemuSpawnError::PreparedLaunchAdmissionChanged)
    ));
    Ok(())
}

#[test]
fn guarded_spawn_rejects_changed_admission_before_revalidation() -> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let wide_contract = wide_test_process_contract()?;
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::File::create(&vmstate_path)?;
    let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        directory.path(),
        &wide_contract,
    )?;
    std::fs::remove_file(&vmstate_path)?;
    std::fs::File::create(&vmstate_path)?;

    let (_cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let changed_contract = QemuChildProcessContract::from_unvalidated_test_descriptors(
        cgroup_write,
        cancellation,
        u32::MAX,
        u64::MAX - 1,
        u64::MAX,
    );
    assert!(matches!(
        spawn_prepared_qemu_child_with_fds_in_directory_guarded(
            &command,
            &prepared,
            4096,
            &changed_contract,
        ),
        Err(QemuSpawnError::PreparedLaunchAdmissionChanged)
    ));
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
    let mut child = spawn_unpinned_test_process_with_resources(
        &current_exe,
        &args,
        child_resources,
        &[(PROBE_ENV, "1"), (SOURCE_FDS_ENV, &source_fds)],
        "spawn child fd probe",
        None,
    )?;

    let status = child.wait()?;

    assert!(status.success());
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
        let mut child = spawn_unpinned_test_process_with_resources(
            &current_exe,
            &args,
            child_resources,
            &[
                (ENV_CLEAR_CHILD_PROBE, "1"),
                (EXPLICIT_ENV_SENTINEL, "explicit-child-value"),
                (SOURCE_FDS_ENV, &source_fds),
            ],
            "spawn child clean-environment probe",
            None,
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
    let child = spawn_unpinned_test_process_with_resources(
        &current_exe,
        &args,
        child_resources,
        &[(PDEATH_CHILD_ENV, "1")],
        "spawn parent-death probe child",
        None,
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

struct GuardedProbeFixture {
    directory: tempfile::TempDir,
    _cgroup_read: OwnedFd,
    command: QemuLaunchCommand,
    contract: QemuChildProcessContract,
    prepared: QemuPreparedRunDirectory,
    args: Vec<String>,
}

impl GuardedProbeFixture {
    fn new(
        child_test: &str,
        directory_access: ProbeChildDirectoryAccess,
    ) -> Result<Self, Box<dyn Error>> {
        let executable = env::current_exe()?;
        let command = guarded_resource_test_command()?
            .with_test_executable(executable.to_string_lossy().into_owned());
        let (cgroup_read, cgroup_write) = pipe_pair()?;
        let cancellation = event_fd_for_test()?;
        let contract = QemuChildProcessContract::for_test(
            cgroup_write,
            cancellation,
            current_file_size_limit()?,
        );
        let directory = tempfile::tempdir()?;
        std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
        std::fs::File::create(directory.path().join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME))?;
        std::fs::File::create(directory.path().join(GUARDED_PROBE_CHILD_MARKER))?;
        if directory_access == ProbeChildDirectoryAccess::WritablePidFile {
            let pid_file = directory.path().join(GUARDED_PROBE_DESCENDANT_PID);
            std::fs::File::create(&pid_file)?;
            std::fs::set_permissions(pid_file, std::fs::Permissions::from_mode(0o666))?;
        }
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o711))?;
        let prepared = QemuPreparedRunDirectory::open_for_test_requirements(
            command.resource_requirements(),
            directory.path(),
            &contract,
        )?;
        let args = vec![String::from("--exact"), child_test.to_owned()];
        Ok(Self {
            directory,
            _cgroup_read: cgroup_read,
            command,
            contract,
            prepared,
            args,
        })
    }

    fn run(
        &self,
        maximum_output_bytes: usize,
        timeout: Duration,
    ) -> Result<QemuGuardedImagePreparationError, Box<dyn Error>> {
        match run_guarded_qemu_setup_probe(
            &self.command,
            &self.args,
            &[],
            maximum_output_bytes,
            timeout,
            &self.prepared,
            &self.contract,
        ) {
            Err(error) => Ok(error),
            Ok(output) => Err(format!(
                "guarded probe unexpectedly succeeded with status {}",
                output.status
            )
            .into()),
        }
    }

    fn descendant_pid(&self) -> Result<rustix::process::Pid, Box<dyn Error>> {
        let pid =
            std::fs::read_to_string(self.directory.path().join(GUARDED_PROBE_DESCENDANT_PID))?;
        let pid = pid.parse::<i32>()?;
        rustix::process::Pid::from_raw(pid).ok_or_else(|| "descendant reported PID zero".into())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProbeChildDirectoryAccess {
    ReadOnly,
    WritablePidFile,
}

struct AdoptedDescendant {
    pid: Option<rustix::process::Pid>,
}

impl AdoptedDescendant {
    const fn new(pid: rustix::process::Pid) -> Self {
        Self { pid: Some(pid) }
    }

    fn terminate_and_reap(mut self) -> rustix::io::Result<()> {
        if let Some(pid) = self.pid.take() {
            terminate_and_reap_adopted_descendant(pid)?;
        }
        Ok(())
    }
}

impl Drop for AdoptedDescendant {
    fn drop(&mut self) {
        if let Some(pid) = self.pid.take() {
            let _ = terminate_and_reap_adopted_descendant(pid);
        }
    }
}

fn terminate_and_reap_adopted_descendant(pid: rustix::process::Pid) -> rustix::io::Result<()> {
    if let Err(error) = rustix::process::kill_process(pid, rustix::process::Signal::KILL)
        && error != rustix::io::Errno::SRCH
    {
        return Err(error);
    }

    match rustix::process::waitpid(Some(pid), rustix::process::WaitOptions::empty())? {
        Some((waited, _status)) if waited == pid => Ok(()),
        _ => Err(rustix::io::Errno::CHILD),
    }
}

fn wide_test_process_contract() -> Result<QemuChildProcessContract, Box<dyn Error>> {
    let (_cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    Ok(QemuChildProcessContract::from_unvalidated_test_descriptors(
        cgroup_write,
        cancellation,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    ))
}

fn open_prepared_run_directory_for_test(
    path: &Path,
) -> Result<QemuPreparedRunDirectory, Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let contract = wide_test_process_contract()?;
    std::fs::write(
        path.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
        b"provisioned",
    )?;
    Ok(QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        path,
        &contract,
    )?)
}

fn guarded_resource_test_command() -> Result<QemuLaunchCommand, Box<dyn Error>> {
    Ok(guarded_resource_test_command_builder()?.build()?)
}

fn guarded_resource_test_command_builder() -> Result<crate::QemuLaunchCommandBuilder, Box<dyn Error>>
{
    let profile = crate::DeterministicLaunchProfile::conservative_default()?;
    let vm = crate::QemuVmLaunchConfig::new(
        "vm-a",
        crate::QemuLaunchArtifact::new(
            ContentHash::from_canonical_material("kernel", "guarded-spawn-test"),
            "/nix/store/33333333333333333333333333333333-crucible-kernel/bzImage",
        ),
        crate::QemuLaunchArtifact::new(
            ContentHash::from_canonical_material("root-image", "guarded-spawn-test"),
            "/nix/store/44444444444444444444444444444444-crucible-root/root.qcow2",
        ),
    );
    let plugin = crate::QemuLaunchPluginConfig::new(
        "/nix/store/22222222222222222222222222222222-crucible-qemu-plugin/lib/libcrucible_qemu_plugin.so",
        0,
    )
    .with_fault_target_node("vm-a");
    Ok(crate::QemuLaunchCommandBuilder::new_for_live_gate(
        profile,
        vm,
        "/nix/store/11111111111111111111111111111111-aos-qemu/bin/qemu-system-x86_64",
        plugin,
        crate::LivePluginGuestArchitecture::X86_64,
    ))
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
