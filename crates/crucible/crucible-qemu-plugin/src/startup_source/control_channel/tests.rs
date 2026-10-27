//! Exercises actual borrowed socket I/O with model Source status tables only.

use super::*;
use std::cell::Cell;
use std::os::unix::net::UnixStream;

thread_local! { static CHECKS: Cell<u32> = const { Cell::new(0) }; }

extern "C" fn acquire(_: u64, _: i32) -> i32 {
    0
}
extern "C" fn check(_: u64) -> i32 {
    0
}
extern "C" fn refuse(_: u64) -> i32 {
    -173
}
extern "C" fn refuse_post(_: u64) -> i32 {
    CHECKS.with(|calls| {
        let old = calls.get();
        calls.set(old + 1);
        if old == 0 { 0 } else { -211 }
    })
}
extern "C" fn slice(_: u64, out: *mut u64) -> i32 {
    // SAFETY: the bounded adapter lends one initialized output for this call.
    unsafe {
        *out = 1_000_000;
    }
    0
}

extern "C" fn one_nanosecond_slice(_: u64, out: *mut u64) -> i32 {
    // SAFETY: the model adapter supplies one initialized output for this call.
    unsafe {
        *out = 1;
    }
    0
}

extern "C" fn complete(_: u64, _: i32) -> i32 {
    0
}

fn socket(owner: &UnixStream, check: super::super::Check) -> SetupControlSocket {
    // SAFETY: the fixture keeps its actual owner alive through the view's use.
    let descriptor = unsafe { BorrowedFd::borrow_raw(owner.as_raw_fd()) };
    SetupControlSocket {
        descriptor,
        installing: Some(InstallObservation {
            plugin_id: 7,
            api: NativeStartupApi {
                acquire,
                check,
                query_slice: slice,
                registration_complete: complete,
            },
            first_refusal: None,
        }),
    }
}

#[test]
fn poll_timeout_preserves_nanoseconds_across_unit_boundaries() -> Result<(), StartupSourceError> {
    for (nanoseconds, seconds, remainder) in [
        (1, 0, 1),
        (999_999, 0, 999_999),
        (1_000_001, 0, 1_000_001),
        (1_000_000_001, 1, 1),
    ] {
        let timeout = installer_poll_timeout(nanoseconds)?;

        assert_eq!(timeout.tv_sec, seconds);
        assert_eq!(timeout.tv_nsec, remainder);
    }
    Ok(())
}

#[test]
fn zero_poll_allowance_is_refused_before_waiting() {
    assert!(matches!(
        installer_poll_timeout(0),
        Err(StartupSourceError::Ownership { .. })
    ));
}

#[test]
fn ready_wait_rechecks_the_original_without_consuming_the_reply() -> io::Result<()> {
    CHECKS.with(|calls| calls.set(0));
    let (mut owner, mut peer) = UnixStream::pair()?;
    peer.write_all(b"ack")?;
    let mut view = socket(&owner, refuse_post);
    let observation = view
        .installing
        .as_mut()
        .ok_or_else(|| io::Error::other("model installing observation is absent"))?;
    observation.api.query_slice = one_nanosecond_slice;

    let error = match observation.wait(owner.as_raw_fd(), libc::POLLIN) {
        Ok(()) => return Err(io::Error::other("expired installing original was admitted")),
        Err(error) => error,
    };

    assert_eq!(
        error
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<StartupSourceError>()),
        Some(&StartupSourceError::NativeStatus { status: -211 }),
    );
    assert_eq!(
        observation.first_refusal,
        Some(StartupSourceError::NativeStatus { status: -211 }),
    );
    let mut reply = [0; 3];
    owner.read_exact(&mut reply)?;
    assert_eq!(&reply, b"ack");
    Ok(())
}

#[test]
fn borrowed_channel_transfers_without_mutating_flags_or_closing_owner() {
    let (owner, mut peer) = UnixStream::pair().unwrap();
    // SAFETY: these read-only queries observe the live fixture-owned socket.
    let flags = unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFL) };
    let mut view = socket(&owner, check);
    view.write_all(b"hello").unwrap();
    let mut received = [0; 5];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, *b"hello");
    peer.write_all(b"ack").unwrap();
    let mut reply = [0; 3];
    view.read_exact(&mut reply).unwrap();
    assert_eq!(reply, *b"ack");
    drop(view);

    assert_eq!(
        // SAFETY: dropping the view leaves the actual owner and OFD intact.
        unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFL) },
        flags
    );
    // SAFETY: the same retained owner still keeps the descriptor open.
    assert!(unsafe { libc::fcntl(owner.as_raw_fd(), libc::F_GETFD) } >= 0);
}

#[test]
fn original_refusal_precedes_io_and_preserves_exact_signed_cause() {
    let (owner, mut peer) = UnixStream::pair().unwrap();
    peer.set_nonblocking(true).unwrap();
    let mut view = socket(&owner, refuse);
    let error = view.write(b"hello").unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<StartupSourceError>(),
        Some(&StartupSourceError::NativeStatus { status: -173 })
    );
    assert_eq!(
        peer.read(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn post_refusal_keeps_transferred_bytes_and_prevents_repeat_io() {
    CHECKS.with(|calls| calls.set(0));
    let (owner, mut peer) = UnixStream::pair().unwrap();
    let mut view = socket(&owner, refuse_post);
    let error = view.write(b"one").unwrap_err();
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<StartupSourceError>(),
        Some(&StartupSourceError::NativeStatus { status: -211 })
    );
    assert!(view.write(b"two").is_err());
    let mut received = [0; 3];
    peer.read_exact(&mut received).unwrap();
    assert_eq!(received, *b"one");
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        peer.read(&mut [0; 3]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[test]
fn hard_io_failure_preserves_primary_error_and_latches_original_post_refusal() {
    CHECKS.with(|calls| calls.set(0));
    let (owner, _peer) = UnixStream::pair().unwrap();
    let mut view = socket(&owner, refuse_post);
    // The fixture owns its endpoint; production never shuts down a borrow.
    owner.shutdown(std::net::Shutdown::Both).unwrap();

    let primary = view.write(b"one").unwrap_err();
    assert_eq!(primary.kind(), io::ErrorKind::BrokenPipe);
    let retained = view.write(b"two").unwrap_err();
    assert_eq!(
        retained
            .get_ref()
            .unwrap()
            .downcast_ref::<StartupSourceError>(),
        Some(&StartupSourceError::NativeStatus { status: -211 }),
    );
}
