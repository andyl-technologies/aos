//! Descriptor-reply carrier tests that do not require a cgroup filesystem.

#![allow(
    clippy::expect_used,
    reason = "Kernel socket fixture failures intentionally panic."
)]

use super::*;

fn pair() -> (DescriptorSubjectSocket, OwnedFd) {
    let (receiver, sender) = uapi::seqpacket_pair().expect("socket pair");
    (
        DescriptorSubjectSocket::from_owned(receiver).expect("configured receiver"),
        sender,
    )
}

#[test]
fn exact_descriptor_replies_retain_subject_and_cloexec_ownership() {
    let (mut receiver, sender) = pair();
    uapi::send_seqpacket(sender.as_fd(), b"hello").expect("send hello");
    let hello = receiver.receive(64, 0).expect("subject-only hello");
    assert_eq!(hello.payload(), b"hello");
    assert!(hello.descriptors().is_empty());
    assert_eq!(
        hello.subject().credentials().pid().get(),
        std::process::id()
    );

    let first = tempfile::tempfile().expect("first transferred file");
    let second = tempfile::tempfile().expect("second transferred file");
    uapi::send_seqpacket_rights(sender.as_fd(), b"reply", &[first.as_fd(), second.as_fd()])
        .expect("send reply");
    let record = receiver.receive(64, 2).expect("exact rights and subject");
    assert_eq!(record.payload(), b"reply");
    assert_eq!(record.descriptors().len(), 2);
    assert_eq!(record.subject().initial_info().pid(), std::process::id());
    assert!(uapi::is_cloexec(record.subject().pidfd().as_fd()).expect("subject CLOEXEC"));
    for fd in record.descriptors() {
        assert!(uapi::is_cloexec(fd.as_fd()).expect("transferred CLOEXEC"));
    }
}

#[test]
fn wrong_descriptor_count_and_oversize_close_the_receiver() {
    for (sent, expected) in [(0, 2), (1, 0), (1, 2), (3, 2)] {
        let (mut receiver, sender) = pair();
        let file = tempfile::tempfile().expect("transferred file");
        if sent == 0 {
            uapi::send_seqpacket(sender.as_fd(), b"reply").expect("send without rights");
        } else {
            uapi::send_seqpacket_rights(sender.as_fd(), b"reply", &vec![file.as_fd(); sent])
                .expect("send wrong count");
        }
        assert!(matches!(
            receiver.receive(64, expected),
            Err(SeqpacketError::Ancillary(_))
        ));
        assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
    }
    let (mut receiver, sender) = pair();
    uapi::send_seqpacket(sender.as_fd(), b"oversized").expect("send oversize");
    assert!(matches!(
        receiver.receive(4, 0),
        Err(SeqpacketError::RecordTooLarge { .. })
    ));
    assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
}

#[test]
fn records_queued_before_identity_configuration_are_not_upgraded() {
    let (receiver, sender) = uapi::seqpacket_pair().expect("socket pair");
    uapi::send_seqpacket(sender.as_fd(), b"early").expect("queue before options");
    let mut receiver = DescriptorSubjectSocket::from_owned(receiver).expect("configure receiver");
    assert!(receiver.receive(64, 0).is_err());
    assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
}

#[test]
fn invalid_bounds_do_not_consume_or_close_the_channel() {
    let (mut receiver, sender) = pair();
    uapi::send_seqpacket(sender.as_fd(), b"hello").expect("send hello");
    for (bytes, descriptors) in [(0, 0), (MAXIMUM_PACKET_BYTES + 1, 0), (64, 3)] {
        assert!(matches!(
            receiver.receive(bytes, descriptors),
            Err(SeqpacketError::InvalidMaximum)
        ));
    }
    assert_eq!(
        receiver.receive(64, 0).expect("still queued").payload(),
        b"hello"
    );
}

#[test]
fn reply_profile_accepts_only_zero_or_two_descriptors() {
    for count in 0..=3 {
        let (mut receiver, sender) = pair();
        let file = tempfile::tempfile().expect("transferred file");
        if count == 0 {
            uapi::send_seqpacket(sender.as_fd(), b"reply").expect("no-rights reply");
        } else {
            uapi::send_seqpacket_rights(sender.as_fd(), b"reply", &vec![file.as_fd(); count])
                .expect("rights reply");
        }
        let result = receiver.receive_reply(64);
        if count == 0 || count == 2 {
            assert_eq!(result.expect("valid count").descriptors().len(), count);
        } else {
            assert!(result.is_err());
            assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
        }
    }
}
