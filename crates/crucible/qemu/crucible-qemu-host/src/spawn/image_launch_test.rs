//! Tests exact generation binding and actual read-only setup descriptor inheritance.

use super::*;

#[test]
fn hot_fork_child_provisioning_retains_original_empty_pair_authority() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    let vmstate = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    let root = directory.path().join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    std::fs::File::create(&vmstate)?;
    let contract = wide_test_process_contract()?;
    let requirements = crate::QemuLaunchResourceRequirements::from_vm_shape(1, 1, true);
    let mut prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        requirements,
        directory.path(),
        &contract,
    )?;
    let foreign = QemuChildProcessContract::from_unvalidated_test_descriptors(
        contract.cgroup_procs.try_clone()?,
        contract.cancellation_event.try_clone()?,
        u32::MAX,
        u64::MAX,
        u64::MAX,
    );

    assert!(!root.exists());
    assert!(matches!(
        prepared.hot_fork_root_overlay_destination(),
        Err(QemuSpawnError::PreparedRootOverlayNotReady { .. })
    ));
    assert_eq!(
        contract.admitted_resource_ceiling(),
        foreign.admitted_resource_ceiling()
    );
    assert!(matches!(
        prepared.provision_hot_fork_child_files(&foreign),
        Err(QemuSpawnError::PreparedLaunchAdmissionChanged)
    ));
    assert!(!root.exists());

    prepared.provision_hot_fork_child_files(&contract)?;
    let original = rustix::fs::fstat(prepared.hot_fork_root_overlay_destination()?)?;
    let vmstate_identity = rustix::fs::fstat(prepared.hot_fork_child_file_destination()?)?;
    assert_eq!(original.st_size, 0);
    assert_eq!(original.st_mode & 0o777, 0o600);
    assert_ne!(
        (original.st_dev, original.st_ino),
        (vmstate_identity.st_dev, vmstate_identity.st_ino)
    );
    prepared.provision_hot_fork_child_files(&contract)?;
    let repeated = rustix::fs::fstat(prepared.hot_fork_root_overlay_destination()?)?;
    assert_eq!(
        (original.st_dev, original.st_ino),
        (repeated.st_dev, repeated.st_ino)
    );

    std::fs::write(&root, b"already filled")?;
    assert!(prepared.provision_hot_fork_child_files(&contract).is_err());
    std::fs::write(&root, b"")?;
    std::fs::write(&vmstate, b"already filled")?;
    assert!(prepared.provision_hot_fork_child_files(&contract).is_err());
    std::fs::write(&vmstate, b"")?;
    let retained = directory.path().join("retained-root");
    std::fs::rename(&root, &retained)?;
    std::fs::File::create(&root)?;
    assert!(matches!(
        prepared.provision_hot_fork_child_files(&contract),
        Err(QemuSpawnError::PreparedRootOverlayChanged { .. })
    ));
    std::fs::remove_file(&root)?;
    std::fs::rename(&retained, &root)?;

    prepared.invalidate_hot_fork_child_file_transfer();
    assert!(prepared.provision_hot_fork_child_files(&contract).is_err());
    assert!(prepared.hot_fork_root_overlay_destination().is_err());
    Ok(())
}

#[test]
fn hot_fork_child_provisioning_never_adopts_a_substituted_destination() -> Result<(), Box<dyn Error>>
{
    let directory = tempfile::tempdir()?;
    std::fs::File::create(directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let contract = wide_test_process_contract()?;
    let mut prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        crate::QemuLaunchResourceRequirements::from_vm_shape(1, 1, true),
        directory.path(),
        &contract,
    )?;
    let root = directory.path().join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    std::fs::File::create(&root)?;

    assert!(prepared.provision_hot_fork_child_files(&contract).is_err());
    std::fs::remove_file(&root)?;
    assert!(prepared.provision_hot_fork_child_files(&contract).is_err());
    assert!(prepared.hot_fork_root_overlay_destination().is_err());
    assert!(!root.exists());
    Ok(())
}

#[test]
fn retained_source_helper_preserves_original_attempt_and_ready_file_authority()
-> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let (cgroup_read, cgroup_write) = pipe_pair()?;
    let cancellation = event_fd_for_test()?;
    let contract =
        QemuChildProcessContract::for_test(cgroup_write, cancellation, current_file_size_limit()?);
    let directory = tempfile::tempdir()?;
    let vmstate_path = directory.path().join(crate::DEFAULT_VMSTATE_FILE_NAME);
    let root_path = directory.path().join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    std::fs::write(&vmstate_path, b"initialized VMState container")?;
    std::fs::write(&root_path, b"initialized source root")?;
    let mut prepared = QemuPreparedRunDirectory::open_for_test_requirements(
        command.resource_requirements(),
        directory.path(),
        &contract,
    )?;
    let executable = env::current_exe()?;
    let args = [
        std::ffi::OsString::from("--exact"),
        std::ffi::OsString::from("spawn::tests::pre_exec_vmstate_name_matches_the_launch_contract"),
    ];

    let fresh = run_guarded_image_tool_for_purpose(
        &executable,
        &args,
        "reject fresh helper on retained source",
        &prepared,
        &contract,
        GuardedImageToolPurpose::FreshLaunch,
    );
    assert!(matches!(
        fresh,
        Err(QemuGuardedImagePreparationError {
            source: QemuSpawnError::PreparedLaunchAdmissionChanged,
            child: None,
        })
    ));
    run_guarded_image_tool_for_purpose(
        &executable,
        &args,
        "run retained source helper",
        &prepared,
        &contract,
        GuardedImageToolPurpose::RetainedHotForkSource,
    )?;
    let mut placement = [0_u8; 2];
    std::fs::File::from(cgroup_read).read_exact(&mut placement)?;
    assert_eq!(&placement, CGROUP_ATTACH_SELF);

    let foreign = QemuChildProcessContract::for_test(
        contract.cgroup_procs.try_clone()?,
        contract.cancellation_event.try_clone()?,
        current_file_size_limit()?,
    );
    assert_eq!(
        contract.admitted_resource_ceiling(),
        foreign.admitted_resource_ceiling()
    );
    assert!(matches!(
        prepared.validate_retained_source_helper_basis(&foreign),
        Err(QemuSpawnError::PreparedLaunchAdmissionChanged)
    ));

    for state in [
        materialization::PreparedRootOverlayMaterialization::Absent,
        materialization::PreparedRootOverlayMaterialization::Updating,
    ] {
        prepared.root_overlay_materialization = state;
        assert!(
            prepared
                .validate_retained_source_helper_basis(&contract)
                .is_err()
        );
    }
    prepared.root_overlay_materialization =
        materialization::PreparedRootOverlayMaterialization::Provisioned;
    prepared.exact_device_state_materialization =
        materialization::PreparedDeviceStateMaterialization::Updating;
    assert!(
        prepared
            .validate_retained_source_helper_basis(&contract)
            .is_err()
    );
    prepared.exact_device_state_materialization =
        materialization::PreparedDeviceStateMaterialization::Provisioned;

    std::fs::write(&root_path, b"")?;
    assert!(
        prepared
            .validate_retained_source_helper_basis(&contract)
            .is_err()
    );
    std::fs::write(&root_path, b"initialized source root")?;
    std::fs::rename(&root_path, directory.path().join("original-root"))?;
    std::fs::write(&root_path, b"replacement root")?;
    assert!(matches!(
        prepared.validate_retained_source_helper_basis(&contract),
        Err(QemuSpawnError::PreparedRootOverlayChanged { .. })
    ));
    std::fs::remove_file(&root_path)?;
    std::fs::rename(directory.path().join("original-root"), &root_path)?;
    std::fs::rename(&vmstate_path, directory.path().join("original-vmstate"))?;
    std::fs::write(&vmstate_path, b"replacement VMState")?;
    assert!(matches!(
        prepared.validate_retained_source_helper_basis(&contract),
        Err(QemuSpawnError::PreparedDeviceStateChanged { .. })
    ));
    Ok(())
}

#[test]
fn guarded_absolute_overlay_is_bound_to_its_exact_generation() -> Result<(), Box<dyn Error>> {
    let command = guarded_resource_test_command()?;
    let directory = Path::new("/pinned/generation");
    let absolute = directory.join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME);
    let args: Vec<_> = command
        .args()
        .iter()
        .map(|arg| {
            arg.replace(
                &format!("file={}", crate::DEFAULT_ROOT_OVERLAY_FILE_NAME),
                &format!("file={}", absolute.display()),
            )
        })
        .collect();

    let launch = guarded_launch_args(&args, true, directory)?;
    let probe = image_launch::guarded_probe_args(&args, true, directory)?;
    assert!(launch.iter().any(|arg| arg.contains("file=/dev/fdset/2")));
    assert!(probe.iter().any(|arg| arg.contains("file=/dev/fdset/2")));
    assert_eq!(probe[1], "fd=7,set=2,opaque=crucible-root-overlay-read");
    assert!(!probe.iter().any(|arg| arg.contains("overlay-write")));
    assert!(
        !launch
            .iter()
            .chain(&probe)
            .any(|arg| arg.contains("file=/pinned/"))
    );

    for foreign in ["/other/generation", "/pinned/generation/../generation"] {
        assert!(guarded_launch_args(&args, true, Path::new(foreign)).is_err());
        assert!(image_launch::guarded_probe_args(&args, true, Path::new(foreign)).is_err());
    }
    let duplicated: Vec<_> = args.iter().chain(args.iter()).cloned().collect();
    assert!(guarded_launch_args(&duplicated, true, directory).is_err());
    assert!(image_launch::guarded_probe_args(&duplicated, true, directory).is_err());
    Ok(())
}

#[test]
fn guarded_probe_exec_inherits_only_read_only_overlay_authority() -> Result<(), Box<dyn Error>> {
    let fixture = GuardedProbeFixture::new(
        "spawn::tests::image_launch_tests::guarded_probe_read_only_overlay_child",
        ProbeChildDirectoryAccess::ReadOnly,
    )?;
    let read = fixture
        .prepared
        .open_direct_root_overlay_for_probe()?
        .ok_or("missing overlay")?;
    let pin = duplicate_cloexec_fd(read.as_raw_fd(), "pin test setup overlay")?;
    let output = run_guarded_qemu_setup_probe_inner(
        &fixture.command,
        GuardedSetupProbeCommand {
            args: &fixture.args,
            root_overlay: Some(&pin),
        },
        &[],
        4096,
        Duration::from_secs(5),
        &fixture.prepared,
        &fixture.contract,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::metadata(
            fixture
                .directory
                .path()
                .join(crate::DEFAULT_ROOT_OVERLAY_FILE_NAME)
        )?
        .len(),
        0
    );
    Ok(())
}

#[test]
fn guarded_probe_read_only_overlay_child() -> Result<(), Box<dyn Error>> {
    if !probe_child_is_active() {
        return Ok(());
    }
    let flags = unsafe {
        // SAFETY: fcntl validates the fixed descriptor inherited by this child.
        libc::fcntl(QEMU_ROOT_OVERLAY_READ_LAUNCH_FD, libc::F_GETFL)
    };
    assert_ne!(flags, -1);
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
    let written = unsafe {
        // SAFETY: pwrite reads one live byte and validates descriptor access.
        libc::pwrite(QEMU_ROOT_OVERLAY_READ_LAUNCH_FD, b"x".as_ptr().cast(), 1, 0)
    };
    assert_eq!(written, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    Ok(())
}

#[test]
fn overlay_relative_name_requires_actual_original_cwd_and_admitted_inode()
-> Result<(), Box<dyn Error>> {
    let fixture = GuardedProbeFixture::new(
        "spawn::tests::image_launch_tests::overlay_relative_name_original_cwd_child",
        ProbeChildDirectoryAccess::ReadOnly,
    )?;
    let output = run_guarded_qemu_setup_probe_inner(
        &fixture.command,
        GuardedSetupProbeCommand {
            args: &fixture.args,
            root_overlay: None,
        },
        &[],
        4096,
        Duration::from_secs(5),
        &fixture.prepared,
        &fixture.contract,
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn overlay_relative_name_original_cwd_child() -> Result<(), Box<dyn Error>> {
    if !probe_child_is_active() {
        return Ok(());
    }
    let directory = env::current_dir()?;
    let prepared = open_prepared_run_directory_for_test(&directory)?;
    let path = directory.join("crucible-hot-fork-overlay-11.qcow2");
    std::fs::write(&path, b"admitted regular overlay")?;
    let file = std::fs::File::open(&path)?;
    let name = prepared.authenticate_hot_fork_overlay_name(std::process::id(), &file, &path)?;
    assert_eq!(name, Path::new("crucible-hot-fork-overlay-11.qcow2"));
    assert!(
        prepared
            .authenticate_hot_fork_overlay_name(u32::MAX, &file, &path)
            .is_err()
    );
    assert!(
        prepared
            .authenticate_hot_fork_overlay_name(
                std::process::id(),
                &file,
                &directory.join("foreign/overlay")
            )
            .is_err()
    );

    std::fs::rename(&path, directory.join("original-overlay"))?;
    std::fs::write(&path, b"replacement regular overlay")?;
    assert!(
        prepared
            .authenticate_hot_fork_overlay_name(std::process::id(), &file, &path)
            .is_err()
    );
    let other = tempfile::tempdir()?;
    std::fs::File::create(other.path().join(crate::DEFAULT_VMSTATE_FILE_NAME))?;
    let foreign = open_prepared_run_directory_for_test(other.path())?;
    let foreign_path = other.path().join("crucible-hot-fork-overlay-11.qcow2");
    std::fs::write(&foreign_path, b"foreign regular overlay")?;
    assert!(
        foreign
            .authenticate_hot_fork_overlay_name(
                std::process::id(),
                &std::fs::File::open(&foreign_path)?,
                &foreign_path
            )
            .is_err()
    );
    Ok(())
}
