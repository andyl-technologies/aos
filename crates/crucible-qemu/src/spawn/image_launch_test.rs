//! Tests exact generation binding and actual read-only setup descriptor inheritance.

use super::*;

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
