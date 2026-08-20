//! Tests extracted from the adjacent production module.

use std::env;
use std::error::Error;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crucible::ContentHash;

use super::*;

const PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_CHILD_PROBE";
const SOURCE_FDS_ENV: &str = "CRUCIBLE_QEMU_SPAWN_SOURCE_FDS";
const CWD_PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_CWD_PROBE";
const PINNED_CWD_PROBE_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PINNED_CWD_PROBE";
const PDEATH_PARENT_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_PARENT_PROBE";
const PDEATH_CHILD_ENV: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PROBE";
const PDEATH_CHILD_PID_PREFIX: &str = "CRUCIBLE_QEMU_SPAWN_PDEATH_CHILD_PID=";
const ENV_CLEAR_PARENT_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_PARENT_PROBE";
const ENV_CLEAR_CHILD_PROBE: &str = "CRUCIBLE_QEMU_SPAWN_ENV_CLEAR_CHILD_PROBE";
const INHERITED_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_INHERITED_SENTINEL";
const EXPLICIT_ENV_SENTINEL: &str = "CRUCIBLE_QEMU_SPAWN_EXPLICIT_SENTINEL";
static TEMP_DIR_SUFFIX: AtomicU64 = AtomicU64::new(0);

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

    let mut child = spawn_process_with_resources(
        &current_exe,
        &args,
        QemuSpawnWorkingDirectory::Inherit,
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
        let error = match spawn_process_with_resources(
            &current_exe,
            &[],
            QemuSpawnWorkingDirectory::Inherit,
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
    let credentials = valid_distinct_credentials()?;
    let error = match QemuChildProcessContract::new(
        temporary.into(),
        duplicate,
        1,
        4096,
        4096,
        credentials,
    ) {
        Err(error) => error,
        Ok(_) => panic!("regular files must not construct a containment contract"),
    };
    assert!(matches!(error, QemuSpawnError::Io { .. }));
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
        Err(QemuSpawnError::PreparedVmStateChanged { .. })
    ));
    Ok(())
}

#[test]
fn pinned_pre_exec_rejects_vmstate_replacement() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::File::create(&vmstate_path)?;
    let prepared = open_prepared_run_directory_for_test(directory.path())?;
    std::fs::remove_file(&vmstate_path)?;
    std::fs::File::create(&vmstate_path)?;

    let (_host, child_resources) = create_spawn_resources(4096)?;
    let current_exe = env::current_exe()?;
    let current_exe = current_exe.to_string_lossy().into_owned();
    let error = match spawn_process_with_resources(
        &current_exe,
        &[],
        QemuSpawnWorkingDirectory::Pinned(&prepared),
        child_resources,
        &[],
        "spawn replaced pinned VMState probe",
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
        QemuSpawnWorkingDirectory::Pinned(&prepared),
        child_resources,
        &[
            (
                PINNED_CWD_PROBE_ENV,
                expected.as_os_str().to_string_lossy().as_ref(),
            ),
            (SOURCE_FDS_ENV, &source_fds),
        ],
        "spawn pinned child cwd probe",
        None,
    )?;

    assert!(child.wait()?.success());
    Ok(())
}

#[test]
fn guarded_preparation_rejects_underprovisioned_launch_before_run_directory_access()
-> Result<(), Box<dyn Error>> {
    let (_cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let contract = QemuChildProcessContract::for_test_with_resources(
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

    let error = match QemuPreparedRunDirectory::open_for_launch(
        &command,
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
fn guarded_spawn_rejects_changed_admission_before_revalidation() -> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let wide_contract = wide_test_process_contract()?;
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    std::fs::File::create(&vmstate_path)?;
    let prepared =
        QemuPreparedRunDirectory::open_for_launch(&command, directory.path(), &wide_contract)?;
    std::fs::remove_file(&vmstate_path)?;
    std::fs::File::create(&vmstate_path)?;

    let (_cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let changed_contract = QemuChildProcessContract::for_test_with_resources(
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
    let mut child = spawn_process_with_resources(
        &current_exe,
        &args,
        QemuSpawnWorkingDirectory::Inherit,
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
        QemuSpawnWorkingDirectory::Path(&run_directory),
        child_resources,
        &[
            (
                CWD_PROBE_ENV,
                expected_directory.as_os_str().to_string_lossy().as_ref(),
            ),
            (SOURCE_FDS_ENV, &source_fds),
        ],
        "spawn child cwd probe",
        None,
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
            QemuSpawnWorkingDirectory::Inherit,
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
    let child = spawn_process_with_resources(
        &current_exe,
        &args,
        QemuSpawnWorkingDirectory::Inherit,
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

fn unique_temp_run_directory(prefix: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));
    std::fs::create_dir(&path)?;
    Ok(path)
}

fn wide_test_process_contract() -> Result<QemuChildProcessContract, Box<dyn Error>> {
    let (_cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    Ok(QemuChildProcessContract::for_test_with_resources(
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
    Ok(QemuPreparedRunDirectory::open_for_launch(
        &command, path, &contract,
    )?)
}

fn guarded_resource_test_command() -> Result<QemuLaunchCommand, Box<dyn Error>> {
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
    )
    .build()?)
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
