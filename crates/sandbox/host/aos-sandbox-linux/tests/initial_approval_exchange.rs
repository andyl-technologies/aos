//! Exercises the real finite approval carrier on the selected AOS VM kernel.
//!
//! The opaque request/signature bytes are transport fixtures. This creates no
//! genuine Source, independently signed approval, installed producer or TPM
//! permission. Kernel feature failures are fatal; this fixture has no skips.

use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::AsFd as _;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use aos_sandbox_linux::seqpacket::initial_approval::{
    INITIAL_APPROVAL_REQUEST_BYTES_V1, InitialApprovalExchangeOriginalV1,
};
use aos_sandbox_linux::seqpacket::{RecordSubjectListener, SeqpacketSocket, bounded};

const REQUEST: [u8; INITIAL_APPROVAL_REQUEST_BYTES_V1] = [7; INITIAL_APPROVAL_REQUEST_BYTES_V1];
const SIGNATURE: [u8; 64] = [8; 64];

fn deadline() -> u64 {
    bounded::boottime()
        .unwrap()
        .checked_add(5_000_000_000)
        .unwrap()
}

fn round_trip(response: Vec<u8>, expected: bool, native_failure: bool) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("approval.sock");
    let mut listener = RecordSubjectListener::bind(&path, 1).unwrap();
    let (release, wait) = mpsc::channel();
    let operator = thread::spawn(move || {
        let mut socket = SeqpacketSocket::connect_retaining(&path).unwrap();
        let request = bounded::receive(&mut socket, REQUEST.len(), deadline()).unwrap();
        assert_eq!(request.payload(), REQUEST);
        let foreign = tempfile::tempfile().unwrap();
        let descriptors = [foreign.as_fd()];
        let mut control = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut ancillary = rustix::net::SendAncillaryBuffer::new(&mut control);
        assert!(ancillary.push(rustix::net::SendAncillaryMessage::ScmRights(&descriptors)));
        assert_eq!(
            rustix::net::sendmsg(
                socket.as_fd().unwrap(),
                &[IoSlice::new(b"foreign right")],
                &mut ancillary,
                rustix::net::SendFlags::DONTWAIT | rustix::net::SendFlags::NOSIGNAL,
            ),
            Err(rustix::io::Errno::PERM)
        );
        socket.send_retaining(&response).unwrap();
        // Keep the actual writer alive until the server retains its subject.
        let _ = wait.recv_timeout(Duration::from_secs(10));
    });
    let mut original = InitialApprovalExchangeOriginalV1::new();

    let result = original.exchange_once_v1(&mut listener, REQUEST, deadline());
    let _ = release.send(());
    operator.join().unwrap();

    assert_eq!(result.is_ok(), expected);
    assert_eq!(original.native_failure_v1().is_some(), native_failure);
    if expected {
        assert_eq!(original.signature_data_v1(), Some(SIGNATURE));
    } else {
        assert!(original.signature_data_v1().is_none());
    }
    let first_cause = original
        .native_failure_v1()
        .map(|cause| std::ptr::from_ref(cause).cast::<()>());

    assert!(
        original
            .exchange_once_v1(&mut listener, [9; REQUEST.len()], deadline())
            .is_err()
    );
    assert!(original.signature_data_v1().is_none());
    assert_eq!(
        original
            .native_failure_v1()
            .map(|cause| std::ptr::from_ref(cause).cast::<()>()),
        first_cause
    );
}

fn premature_response_is_not_adopted() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("approval.sock");
    let mut listener = RecordSubjectListener::bind(&path, 1).unwrap();
    let (ready, await_ready) = mpsc::channel();
    let (release, wait) = mpsc::channel();
    let operator = thread::spawn(move || {
        let mut socket = SeqpacketSocket::connect_retaining(&path).unwrap();
        socket.send_retaining(&SIGNATURE).unwrap();
        ready.send(()).unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(10));
    });
    await_ready.recv_timeout(Duration::from_secs(10)).unwrap();
    let mut original = InitialApprovalExchangeOriginalV1::new();

    let result = original.exchange_once_v1(&mut listener, REQUEST, deadline());
    let _ = release.send(());
    operator.join().unwrap();

    assert!(result.is_err());
    assert!(original.signature_data_v1().is_none());
    assert!(original.native_failure_v1().is_some());
}

fn expired_deadline_preserves_the_unaccepted_connection() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("approval.sock");
    let mut listener = RecordSubjectListener::bind(&path, 1).unwrap();
    let _operator = SeqpacketSocket::connect_retaining(&path).unwrap();
    let mut original = InitialApprovalExchangeOriginalV1::new();

    assert!(
        original
            .exchange_once_v1(&mut listener, REQUEST, 0)
            .is_err()
    );

    assert!(original.signature_data_v1().is_none());
    assert!(original.native_failure_v1().is_none());
    assert!(listener.accept_retaining().is_ok());
}

fn main() {
    round_trip(SIGNATURE.to_vec(), true, false);
    round_trip(vec![8; 63], false, false);
    round_trip(vec![8; 65], false, true);
    premature_response_is_not_adopted();
    expired_deadline_preserves_the_unaccepted_connection();
    println!("finite initial approval transport: five native cases PASS");
}
