//! Observes real socket refusal and inline native-error ownership.

use super::*;
use crucible_host_resources::test_support::TestAllocationObserver;
use std::error::Error;

#[cfg(target_pointer_width = "64")]
#[test]
fn typed_native_cause_fits_the_existing_target_error_extent() {
    // Existing callers price a 64-byte target error on the supported 64-bit
    // hosts. Adding the raw native cause must not enlarge their inline history.
    assert_eq!(std::mem::size_of::<QemuShutdownTargetError>(), 64);
}

#[test]
fn native_errors_preserve_typed_causes_and_clone_without_allocating() {
    for code in [libc::EPIPE, libc::ECHILD, libc::ESRCH, libc::EPERM] {
        let original = io::Error::from_raw_os_error(code);
        let diagnostic = format!("native cleanup failed: {original}");

        let ((error, cloned), counts) = TestAllocationObserver::count(|| {
            let error = QemuShutdownTargetError::io("native cleanup", original);
            let cloned = error.clone();
            (error, cloned)
        });

        assert_eq!(counts.allocations, 0);
        assert_eq!(counts.reallocations, 0);
        assert!(!counts.overflow);
        assert_eq!(error, cloned);
        assert!(error.message.is_empty());
        assert_eq!(error.to_string(), diagnostic);
        assert_eq!(cloned.to_string(), diagnostic);
        assert!(error.operational_supervision_source().is_none());
        for observer in [&error, &cloned] {
            let source = observer
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap();
            assert_eq!(source.raw_os_error(), Some(code));
            assert!(std::ptr::eq(source, observer.io_source().unwrap()));
        }
    }
}

#[cfg(unix)]
#[test]
fn actual_qmp_socket_refusal_retains_kernel_error_without_allocating() {
    let (mut writer, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(peer);

    let ((error, cloned), counts) = TestAllocationObserver::count(|| {
        let error = crate::send_qmp_quit_command(&mut writer).unwrap_err();
        let cloned = error.clone();
        (error, cloned)
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(error.operation, "send QMP quit");
    assert_eq!(error.io_source().unwrap().raw_os_error(), Some(libc::EPIPE));
    assert_eq!(error, cloned);
    assert_eq!(
        cloned
            .source()
            .unwrap()
            .downcast_ref::<io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(libc::EPIPE),
    );
}

#[cfg(unix)]
#[test]
fn actual_control_socket_refusal_retains_kernel_error_without_allocating() {
    let (mut writer, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(peer);

    let (error, counts) =
        TestAllocationObserver::count(|| crate::send_control_quit_frame(&mut writer).unwrap_err());

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(error.operation, "send control Quit");
    assert_eq!(error.io_source().unwrap().raw_os_error(), Some(libc::EPIPE));
}

#[test]
fn successful_control_write_matches_the_frozen_protocol_without_allocating() {
    use crucible_qemu_protocol::{ControlTag, GOLDEN_CONTROL_VECTORS, HostMsg};

    let golden = GOLDEN_CONTROL_VECTORS
        .iter()
        .find(|vector| vector.tag == ControlTag::Quit)
        .unwrap();
    let mut storage = [0; 32];
    let mut writer = io::Cursor::new(storage.as_mut_slice());

    let (result, counts) =
        TestAllocationObserver::count(|| crate::send_control_quit_frame(&mut writer));

    result.unwrap();
    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    let written = writer.position() as usize;
    assert_eq!(&storage[..written], golden.frame);
    assert_eq!(crucible_qemu_protocol::CONTROL_QUIT_FRAME, golden.frame);
    assert_eq!(
        crucible_qemu_protocol::control_decode_host_msg(&storage[..written]).unwrap(),
        HostMsg::Quit,
    );
}

#[test]
fn native_pid_range_refusal_precedes_signaling_without_allocating() {
    let (error, counts) = TestAllocationObserver::count(|| {
        crate::shutdown::signal_child(u32::MAX, libc::SIGTERM, "signal child").unwrap_err()
    });

    assert_eq!(counts.allocations, 0);
    assert_eq!(counts.reallocations, 0);
    assert!(!counts.overflow);
    assert_eq!(error.operation, "signal child");
    assert_eq!(
        error.message,
        "child process identifier exceeds the native PID range"
    );
    assert!(error.io_source().is_none());
    assert!(error.source().is_none());
}

#[test]
fn authored_io_errors_keep_the_existing_message_and_supervision_stays_typed() {
    let source = io::Error::other("authored target failure");
    let error = QemuShutdownTargetError::io("target adapter", source);
    assert_eq!(error.message, "authored target failure");
    assert!(error.io_source().is_none());
    assert_eq!(
        error.to_string(),
        "target adapter failed: authored target failure"
    );

    let first = HostSupervisionError::Unavailable;
    let error = QemuShutdownTargetError::operational_supervision("child cleanup", first);
    assert_eq!(error.operational_supervision_source(), Some(first));
    assert_eq!(
        error
            .source()
            .unwrap()
            .downcast_ref::<HostSupervisionError>(),
        Some(&first)
    );
    assert!(error.io_source().is_none());
}
