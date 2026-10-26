//! Checks actual descriptor observations and allocation-free diagnostic conversion.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use std::error::Error;
use std::os::fd::AsRawFd;

#[derive(Debug)]
struct IoPayload(Box<str>);

impl std::fmt::Display for IoPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for IoPayload {}

#[test]
fn closed_control_check_conversion_preserves_labels_and_payloads_without_allocating() {
    for (operation, label) in [
        (
            ControlCheckOperation::PinDirectory,
            "pin QEMU attempt cgroup directory",
        ),
        (
            ControlCheckOperation::IdentifyPinnedDirectory,
            "identify pinned QEMU attempt cgroup",
        ),
        (
            ControlCheckOperation::IdentifyNamedDirectory,
            "identify named QEMU attempt cgroup",
        ),
        (
            ControlCheckOperation::RetainTargetCancellation,
            "retain pooled Target cancellation",
        ),
        (
            ControlCheckOperation::MaintainTargetDispatcher,
            "maintain actual Target dispatcher",
        ),
    ] {
        let path = PathBuf::from("component/pinned-control");
        let path_pointer = path.as_os_str().as_encoded_bytes().as_ptr();
        let payload = IoPayload(String::from("existing control failure").into_boxed_str());
        let payload_pointer = payload.0.as_ptr();
        let error = ControlCheckError::io(operation, path, io::Error::other(payload));
        let display = error.to_string();

        let (converted, counts) =
            TestAllocationObserver::count(|| LinuxQemuCgroupError::from(error));

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(converted.to_string(), display);
        let LinuxQemuCgroupError::Io {
            operation: actual,
            path,
            source,
        } = converted
        else {
            panic!("the existing general boundary must retain its I/O variant");
        };
        assert_eq!(actual, label);
        assert_eq!(path.as_os_str().as_encoded_bytes().as_ptr(), path_pointer);
        assert_eq!(
            source
                .get_ref()
                .unwrap()
                .downcast_ref::<IoPayload>()
                .unwrap()
                .0
                .as_ptr(),
            payload_pointer,
        );
    }

    for error in [
        ControlCheckError::directory_identity(PathBuf::from("component/changed-directory")),
        ControlCheckError::watcher_already_started(PathBuf::from("component/started-watcher")),
    ] {
        let path_pointer = error.path.as_os_str().as_encoded_bytes().as_ptr();
        let display = error.to_string();
        let (converted, counts) =
            TestAllocationObserver::count(|| LinuxQemuCgroupError::from(error));

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(converted.to_string(), display);
        let path = match &converted {
            LinuxQemuCgroupError::DirectoryIdentity { path }
            | LinuxQemuCgroupError::WatcherAlreadyStarted { path } => path,
            _ => panic!("the original control-state variant must survive"),
        };
        assert_eq!(path.as_os_str().as_encoded_bytes().as_ptr(), path_pointer);
        assert!(converted.source().is_none());
    }
}

#[test]
fn named_directory_check_rejects_replacement_and_symlink() {
    let root = tempfile::tempdir().unwrap();
    let named = root.path().join("named");
    let replacement = root.path().join("replacement");
    let retired = root.path().join("retired");
    std::fs::create_dir(&named).unwrap();
    std::fs::create_dir(&replacement).unwrap();
    let parent = rustix::fs::open(
        root.path(),
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .unwrap();
    let pinned = open_directory_at(&parent, "named", &named).unwrap();

    verify_directory_identity(&parent, "named", &pinned, &named).unwrap();
    std::fs::rename(&named, &retired).unwrap();
    std::fs::rename(&replacement, &named).unwrap();
    let changed = verify_directory_identity(&parent, "named", &pinned, &named).unwrap_err();
    assert!(matches!(
        LinuxQemuCgroupError::from(changed),
        LinuxQemuCgroupError::DirectoryIdentity { path } if path == named
    ));

    std::fs::remove_dir(&named).unwrap();
    std::os::unix::fs::symlink("retired", &named).unwrap();
    let symlink = verify_directory_identity(&parent, "named", &pinned, &named).unwrap_err();
    assert!(matches!(
        LinuxQemuCgroupError::from(symlink),
        LinuxQemuCgroupError::Io {
            operation: "pin QEMU attempt cgroup directory",
            ..
        }
    ));
}

#[test]
fn target_cancellation_duplicate_preserves_cloexec_and_actual_failure() {
    let descriptor = rustix::event::eventfd(0, rustix::event::EventfdFlags::CLOEXEC).unwrap();
    let duplicate =
        retain_target_cancellation(descriptor.as_raw_fd(), Path::new("component/event")).unwrap();
    assert_ne!(descriptor.as_raw_fd(), duplicate.as_raw_fd());
    drop(descriptor);
    assert!(
        rustix::io::fcntl_getfd(&duplicate)
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );

    let invalid = retain_target_cancellation(-1, Path::new("component/invalid-event")).unwrap_err();
    let LinuxQemuCgroupError::Io {
        operation, source, ..
    } = invalid.into()
    else {
        panic!("the actual duplication failure must remain an I/O cause");
    };
    assert_eq!(operation, "retain pooled Target cancellation");
    assert_eq!(source.raw_os_error(), Some(libc::EBADF));
}
