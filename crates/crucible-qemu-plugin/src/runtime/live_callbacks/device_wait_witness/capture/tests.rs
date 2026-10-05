//! Genuine full/closed FIFO and regular-cursor noninterference controls.

use super::*;
use std::io::{Read, Seek, Write};

fn flags(file: &File, operation: i32) -> i32 {
    // SAFETY: the descriptor is live and these commands read only its flags.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), operation) };
    assert!(flags >= 0, "flag query: {}", io::Error::last_os_error());
    flags
}

#[cfg(target_os = "linux")]
fn pipe() -> (File, File) {
    let mut descriptors = [-1; 2];
    // SAFETY: storage has two writable descriptor slots; successful creation
    // transfers each owned descriptor exactly once into a File below.
    let status = unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(status, 0);
    use std::os::fd::FromRawFd;
    // SAFETY: pipe2 returned the two distinct descriptors owned above.
    unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    }
}

#[cfg(target_os = "linux")]
#[test]
fn genuine_fifo_full_and_closed_reader_keep_original_flags_and_process_alive() {
    assert!(
        sigpipe_is_ignored().unwrap_or_else(|e| panic!("disposition: {e}")),
        "Rust test process ignores SIGPIPE"
    );
    let (reader, original) = pipe();
    let original_flags = flags(&original, libc::F_GETFL);
    let mut capture = destination(&original).unwrap_or_else(|e| panic!("private FIFO: {e}"));
    assert_eq!(flags(&original, libc::F_GETFL), original_flags);
    assert_eq!(
        flags(&capture, libc::F_GETFD) & libc::FD_CLOEXEC,
        libc::FD_CLOEXEC
    );
    assert_ne!(flags(&capture, libc::F_GETFL) & libc::O_NONBLOCK, 0);
    let bytes = [1_u8; 512];
    loop {
        match capture.write(&bytes) {
            Ok(length) => assert_eq!(length, bytes.len()),
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                break;
            }
        }
    }
    assert_eq!(flags(&original, libc::F_GETFL), original_flags);
    drop(reader);
    let error = capture
        .write(&bytes)
        .err()
        .unwrap_or_else(|| panic!("closed FIFO accepted bytes"));
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(flags(&original, libc::F_GETFL), original_flags);
    drop(capture);
    // An anonymous pipe may reopen despite having no reader. The one bounded
    // write still returns EPIPE under the already-ignored signal disposition.
    let mut reopened = destination(&original).unwrap_or_else(|e| panic!("closed FIFO reopen: {e}"));
    assert_eq!(
        reopened
            .write(&bytes)
            .err()
            .unwrap_or_else(|| panic!("reopened closed FIFO accepted bytes"))
            .kind(),
        io::ErrorKind::BrokenPipe
    );
}

#[test]
fn regular_capture_keeps_shared_cursor_cloexec_and_owned_lifetime() {
    let path = std::env::temp_dir().join(format!(
        "device-wait-cursor-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let mut original = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|e| panic!("capture: {e}"));
    std::fs::remove_file(path).unwrap_or_else(|e| panic!("unlink: {e}"));
    let original_flags = flags(&original, libc::F_GETFL);
    original
        .write_all(b"before\n")
        .unwrap_or_else(|e| panic!("original write: {e}"));
    let mut capture = destination(&original).unwrap_or_else(|e| panic!("capture clone: {e}"));
    assert_eq!(
        flags(&capture, libc::F_GETFD) & libc::FD_CLOEXEC,
        libc::FD_CLOEXEC
    );
    let object = original
        .metadata()
        .unwrap_or_else(|e| panic!("capture identity: {e}"));
    let fd = capture.as_raw_fd();
    assert_eq!(
        capture
            .write(b"diagnostic\n")
            .unwrap_or_else(|e| panic!("capture write: {e}")),
        11
    );
    original
        .write_all(b"after\n")
        .unwrap_or_else(|e| panic!("original tail: {e}"));
    assert_eq!(flags(&original, libc::F_GETFL), original_flags);
    drop(capture);
    // Another parallel test may reuse the descriptor number. It must not
    // retain this test's unlinked capture object after the owned File is dropped.
    assert!(
        std::fs::metadata(format!("/proc/self/fd/{fd}"))
            .map(|metadata| (metadata.dev(), metadata.ino()) != (object.dev(), object.ino()))
            .unwrap_or(true)
    );
    original.rewind().unwrap_or_else(|e| panic!("rewind: {e}"));
    let mut bytes = Vec::new();
    original
        .read_to_end(&mut bytes)
        .unwrap_or_else(|e| panic!("read: {e}"));
    assert_eq!(bytes, b"before\ndiagnostic\nafter\n");
}

#[cfg(target_os = "linux")]
#[test]
fn genuine_idle_callback_drops_full_or_closed_fifo_without_changing_original_advance() {
    use crate::runtime::live_callbacks::{
        idle_plan_witness::IdlePlanWitness, tests::test_live_state,
    };
    use crucible_shmem::{AdvanceStopCondition, KIND_VM, NodeSlot, authorize_advance_ceiling};
    use std::ffi::OsStr;
    use std::sync::Mutex;

    let (reader, original) = pipe();
    let original_flags = flags(&original, libc::F_GETFL);
    let mut fill = destination(&original).unwrap_or_else(|error| panic!("capture: {error}"));
    loop {
        match fill.write(&[1_u8; 512]) {
            Ok(length) => assert_eq!(length, 512),
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
                break;
            }
        }
    }
    let mut reader = Some(reader);
    for closed in [false, true] {
        if closed {
            drop(reader.take());
        }
        let slot = NodeSlot::new(KIND_VM);
        let ceiling = authorize_advance_ceiling(0, 10, None)
            .unwrap_or_else(|error| panic!("ceiling: {error}"));
        slot.publish_scheduler_advance(ceiling, AdvanceStopCondition::Ceiling)
            .unwrap_or_else(|error| panic!("publication: {error}"));
        let mut state =
            test_live_state(48, 1, 0, &slot).unwrap_or_else(|error| panic!("state: {error}"));
        state
            .on_vcpu_init(0)
            .unwrap_or_else(|error| panic!("init: {error}"));
        let mut witness = IdlePlanWitness::from_setting(Some(OsStr::new("256")));
        witness.destination = Some(Mutex::new(
            original
                .try_clone()
                .unwrap_or_else(|error| panic!("duplicate: {error}")),
        ));
        state.idle_plan_witness = witness;
        assert_eq!(state.on_vcpu_idle(0, 0), Ok(()));
        assert!(state.idle_advance_is_pending());
        assert_eq!(slot.snapshot().current_icount, 0);
        assert_eq!(slot.snapshot().idle_wake_icount, 10);
        assert_eq!(flags(&original, libc::F_GETFL), original_flags);
    }
}
