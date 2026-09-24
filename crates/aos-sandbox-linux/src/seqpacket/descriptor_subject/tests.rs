//! Descriptor-reply carrier tests that do not require a cgroup filesystem.

#![allow(
    clippy::expect_used,
    reason = "Kernel socket fixture failures intentionally panic."
)]

use super::*;
use std::os::unix::fs::MetadataExt as _;
use std::process::{Command, Stdio};

use crate::seqpacket::process_tests::{finish_connector, spawn_connector};

const ORIGIN_DESCRIPTOR_DROP_FIXTURE_ENV: &str = "AOS_DESCRIPTOR_SUBJECT_ORIGIN_DROP_FIXTURE_V1";
const PEER_LOSS_FIXTURE_ENV: &str = "AOS_DESCRIPTOR_SUBJECT_PEER_LOSS_FIXTURE_V1";

fn pair() -> (DescriptorSubjectSocket, OwnedFd) {
    let (receiver, sender) = uapi::seqpacket_pair().expect("socket pair");
    (
        DescriptorSubjectSocket::from_owned(receiver).expect("configured receiver"),
        sender,
    )
}

#[test]
fn accepted_endpoint_requires_the_exact_bound_filesystem_path() {
    let directory = tempfile::tempdir().expect("create socket-path fixture directory");
    let expected = directory.path().join("expected.sock");
    let substituted = directory.path().join("substituted.sock");
    let listener = uapi::bind_record_subject_listener(&expected, 1).expect("bind expected socket");
    uapi::enable_seqpacket_identity(listener.as_fd()).expect("configure expected listener");
    let _connector = uapi::connect_seqpacket(&expected).expect("connect expected socket");
    let accepted = uapi::accept_record_subject_socket(listener.as_fd()).expect("accept endpoint");
    let endpoint = DescriptorSubjectSocket::from_owned(accepted).expect("adopt accepted endpoint");

    endpoint
        .require_local_filesystem_path(&expected)
        .expect("match expected local path");
    assert!(
        endpoint
            .require_local_filesystem_path(&substituted)
            .is_err()
    );

    let (unnamed, _peer) = pair();
    assert!(unnamed.require_local_filesystem_path(&expected).is_err());
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
fn received_descriptor_record_binds_only_to_its_exact_socket() {
    let (mut receiver, sender) = pair();
    uapi::send_seqpacket(sender.as_fd(), b"bound").expect("send bound record");
    super::super::socket_binding::reset_current_query_count();
    let record = receiver.receive(64, 0).expect("receive bound record");
    let peer = receiver.peer() as *const ConnectionPeerIdentity;
    assert_eq!(super::super::socket_binding::current_query_count(), 0);

    let bound = receiver.bind_received(record).expect("bind exact socket");

    assert_eq!(super::super::socket_binding::current_query_count(), 1);
    assert_eq!(bound.payload(), b"bound");
    assert!(bound.descriptors().is_empty());
    assert_eq!(bound.subject().initial_info().pid(), std::process::id());
    assert_eq!(bound.peer() as *const ConnectionPeerIdentity, peer);
    let (payload, subject, descriptors, retained_peer) = bound.into_parts();
    assert_eq!(payload, b"bound");
    assert!(descriptors.is_empty());
    assert_eq!(subject.initial_info().pid(), std::process::id());
    assert_eq!(retained_peer as *const ConnectionPeerIdentity, peer);
}

#[test]
fn same_socket_duplicate_accepts_descriptor_record_origin() {
    let (mut receiver, sender) = pair();
    let duplicate_fd = uapi::duplicate_at_least(receiver.as_fd().expect("receiver fd"), 0)
        .expect("duplicate receiver");
    let mut duplicate = DescriptorSubjectSocket::from_owned(duplicate_fd).expect("adopt duplicate");
    uapi::send_seqpacket(sender.as_fd(), b"duplicate").expect("send duplicate record");
    let record = receiver.receive(64, 0).expect("receive through source");
    let duplicate_peer = duplicate.peer() as *const ConnectionPeerIdentity;

    let bound = duplicate
        .bind_received(record)
        .expect("bind through same-socket duplicate");

    assert_eq!(bound.payload(), b"duplicate");
    assert_eq!(
        bound.peer() as *const ConnectionPeerIdentity,
        duplicate_peer
    );
}

#[test]
fn independent_descriptor_socket_rejects_origin_and_closes() {
    let (mut first_receiver, first_sender) = pair();
    let (mut second_receiver, _second_sender) = pair();
    uapi::send_seqpacket(first_sender.as_fd(), b"foreign").expect("send foreign record");
    let record = first_receiver
        .receive(64, 0)
        .expect("receive foreign record");

    assert!(matches!(
        second_receiver.bind_received(record),
        Err(error)
            if error.category() == crate::seqpacket::RecordBindingErrorCategory::OriginMismatch
    ));
    assert!(matches!(
        second_receiver.as_fd(),
        Err(SeqpacketError::Closed)
    ));
}

#[test]
fn opposite_descriptor_endpoint_rejects_origin_and_closes() {
    let (mut receiver, sender_fd) = pair();
    let duplicate_sender =
        uapi::duplicate_at_least(sender_fd.as_fd(), 0).expect("duplicate sender");
    let mut sender =
        DescriptorSubjectSocket::from_owned(sender_fd).expect("adopt sending endpoint");
    uapi::send_seqpacket(duplicate_sender.as_fd(), b"opposite").expect("send opposite record");
    let record = receiver.receive(64, 0).expect("receive record");

    assert!(matches!(
        sender.bind_received(record),
        Err(error)
            if error.category() == crate::seqpacket::RecordBindingErrorCategory::OriginMismatch
    ));
    assert!(matches!(sender.as_fd(), Err(SeqpacketError::Closed)));
}

#[test]
fn origin_mismatch_drops_transferred_descriptors_in_isolated_process() {
    if std::env::var_os(ORIGIN_DESCRIPTOR_DROP_FIXTURE_ENV).as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        run_origin_descriptor_drop_fixture();
        return;
    }

    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "seqpacket::descriptor_subject::tests::origin_mismatch_drops_transferred_descriptors_in_isolated_process",
            "--nocapture",
        ])
        .env(ORIGIN_DESCRIPTOR_DROP_FIXTURE_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("run isolated descriptor-drop fixture");
    assert!(status.success(), "descriptor-drop fixture failed: {status}");
}

fn run_origin_descriptor_drop_fixture() {
    use std::os::fd::AsRawFd as _;

    let (mut first_receiver, first_sender) = pair();
    let (mut second_receiver, _second_sender) = pair();
    let file = tempfile::tempfile().expect("transferred file");
    uapi::send_seqpacket_rights(first_sender.as_fd(), b"foreign", &[file.as_fd()])
        .expect("send foreign descriptor record");
    let record = first_receiver
        .receive(64, 1)
        .expect("receive descriptor record");
    let received_fd = record.descriptors()[0].as_raw_fd();

    assert!(matches!(
        second_receiver.bind_received(record),
        Err(error)
            if error.category() == crate::seqpacket::RecordBindingErrorCategory::OriginMismatch
    ));
    assert!(!uapi::raw_fd_is_open(received_fd));
    assert!(matches!(
        second_receiver.as_fd(),
        Err(SeqpacketError::Closed)
    ));
}

#[test]
fn production_sender_transfers_only_bounded_exact_tables() {
    let (receiver, sender) = uapi::seqpacket_pair().expect("socket pair");
    let mut receiver = DescriptorSubjectSocket::from_owned(receiver).expect("configured receiver");
    let mut sender = DescriptorSubjectSocket::from_owned(sender).expect("configured sender");
    let first = tempfile::tempfile().expect("first transferred file");
    let second = tempfile::tempfile().expect("second transferred file");

    sender
        .send_with_descriptors(b"one", &[first.as_fd()])
        .expect("one descriptor");
    assert_eq!(
        receiver
            .receive(64, 1)
            .expect("one descriptor record")
            .descriptors()
            .len(),
        1
    );

    sender
        .send_with_descriptors(b"two", &[first.as_fd(), second.as_fd()])
        .expect("two descriptors");
    let expected_identities = [first.metadata(), second.metadata()].map(|metadata| {
        let metadata = metadata.expect("sender descriptor metadata");
        (metadata.dev(), metadata.ino())
    });
    let record = receiver.receive(64, 2).expect("two descriptor record");
    let received_identities: Vec<_> = record
        .descriptors()
        .iter()
        .map(|descriptor| {
            let metadata = std::fs::File::from(descriptor.try_clone().expect("clone received fd"))
                .metadata()
                .expect("received descriptor metadata");
            (metadata.dev(), metadata.ino())
        })
        .collect();
    assert_eq!(received_identities, expected_identities);

    assert!(matches!(
        sender.send_with_descriptors(b"none", &[]),
        Err(SeqpacketError::InvalidMaximum)
    ));
    assert!(matches!(
        sender.send_with_descriptors(b"three", &[first.as_fd(), second.as_fd(), first.as_fd()]),
        Err(SeqpacketError::InvalidMaximum)
    ));
    assert!(matches!(
        sender.send_with_descriptors(b"", &[first.as_fd()]),
        Err(SeqpacketError::InvalidMaximum)
    ));

    sender
        .send(b"still-open")
        .expect("invalid bounds are inert");
    assert_eq!(
        receiver
            .receive(64, 0)
            .expect("record after invalid bounds")
            .payload(),
        b"still-open"
    );
}

#[test]
fn closed_kernel_export_profile_transfers_three_ordered_opath_descriptors() {
    let (left, right) = uapi::seqpacket_pair().expect("socket pair");
    let mut sender = DescriptorSubjectSocket::from_owned(left).expect("configured sender");
    let mut receiver = DescriptorSubjectSocket::from_owned(right).expect("configured receiver");
    let directories = [
        tempfile::tempdir().expect("clone directory"),
        tempfile::tempdir().expect("origin directory"),
        tempfile::tempdir().expect("cgroup directory"),
    ];
    let fds = directories.map(|directory| {
        rustix::fs::open(
            directory.path(),
            rustix::fs::OFlags::PATH | rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .expect("open independent O_PATH")
    });
    let expected: [(u64, u64); 3] = std::array::from_fn(|index| {
        let fd = &fds[index];
        let stat = rustix::fs::fstat(fd).expect("sender identity");
        (stat.st_dev, stat.st_ino)
    });

    sender
        .send_kernel_export_three(
            b"AOSKGQ03",
            [fds[0].as_fd(), fds[1].as_fd(), fds[2].as_fd()],
        )
        .expect("send three roles");
    let record = receiver
        .receive_kernel_export_three(856)
        .expect("receive three roles");
    assert_eq!(record.payload(), b"AOSKGQ03");
    let received: Vec<_> = record
        .descriptors()
        .iter()
        .map(|fd| {
            let stat = rustix::fs::fstat(fd).expect("received identity");
            assert!(
                rustix::fs::fcntl_getfl(fd)
                    .expect("status")
                    .contains(rustix::fs::OFlags::PATH)
            );
            assert!(uapi::is_cloexec(fd.as_fd()).expect("CLOEXEC"));
            (stat.st_dev, stat.st_ino)
        })
        .collect();
    assert_eq!(received, expected);
    assert_ne!(received[0], received[1]);
    assert_ne!(received[1], received[2]);
}

#[test]
fn closed_kernel_export_profile_rejects_missing_extra_and_swapped_roles() {
    let first = tempfile::tempfile().expect("first role");
    let second = tempfile::tempfile().expect("second role");
    let third = tempfile::tempfile().expect("third role");
    let fourth = tempfile::tempfile().expect("extra role");

    for descriptors in [
        vec![first.as_fd(), second.as_fd()],
        vec![first.as_fd(), second.as_fd(), third.as_fd(), fourth.as_fd()],
    ] {
        let (mut receiver, sender) = pair();
        uapi::send_seqpacket_rights(sender.as_fd(), b"AOSKGQ03", &descriptors)
            .expect("send malformed descriptor count");
        assert!(receiver.receive_kernel_export_three(856).is_err());
    }

    let (left, right) = uapi::seqpacket_pair().expect("socket pair");
    let mut sender = DescriptorSubjectSocket::from_owned(left).expect("configured sender");
    let mut receiver = DescriptorSubjectSocket::from_owned(right).expect("configured receiver");
    sender
        .send_kernel_export_three(b"AOSKGQ03", [second.as_fd(), first.as_fd(), third.as_fd()])
        .expect("send swapped roles");
    let record = receiver
        .receive_kernel_export_three(856)
        .expect("receive exact count");
    let first_expected = first.metadata().expect("first metadata");
    let first_received = rustix::fs::fstat(&record.descriptors()[0]).expect("first received");
    assert_ne!(
        (first_received.st_dev, first_received.st_ino),
        (first_expected.dev(), first_expected.ino())
    );
}

#[test]
fn closed_kernel_export_profile_closes_after_peer_loss() {
    if std::env::var_os(PEER_LOSS_FIXTURE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        // Parallel tests may fork while this socket is open, retaining the
        // receiver in a child after the parent drops it.
        let status = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "seqpacket::descriptor_subject::tests::closed_kernel_export_profile_closes_after_peer_loss",
                "--nocapture",
            ])
            .env(PEER_LOSS_FIXTURE_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("run isolated peer-loss fixture");
        assert!(status.success(), "peer-loss fixture failed: {status}");
        return;
    }

    let (sender, receiver) = uapi::seqpacket_pair().expect("socket pair");
    let mut sender = DescriptorSubjectSocket::from_owned(sender).expect("configured sender");
    let first = tempfile::tempfile().expect("first role");
    let second = tempfile::tempfile().expect("second role");
    let third = tempfile::tempfile().expect("third role");
    drop(receiver);

    assert!(
        sender
            .send_kernel_export_three(b"AOSKGQ03", [first.as_fd(), second.as_fd(), third.as_fd()],)
            .is_err()
    );
    assert!(matches!(sender.as_fd(), Err(SeqpacketError::Closed)));
}

#[test]
fn packet_capacity_rejects_invalid_bounds_without_closing() {
    let (socket, _sender) = pair();

    for maximum in [0, MAXIMUM_PACKET_BYTES + 1] {
        assert!(matches!(
            socket.provision_packet_capacity(maximum),
            Err(SeqpacketError::InvalidMaximum)
        ));
    }
    assert!(socket.as_fd().is_ok());
}

#[test]
fn small_provisioned_packet_transfers_exactly() {
    let (left, right) = uapi::seqpacket_pair().expect("socket pair");
    let mut left = DescriptorSubjectSocket::from_owned(left).expect("configured left");
    let mut right = DescriptorSubjectSocket::from_owned(right).expect("configured right");
    let payload = vec![0xa5; 4096];

    left.provision_packet_capacity(4096)
        .expect("provision left packet capacity");
    right
        .provision_packet_capacity(4096)
        .expect("provision right packet capacity");

    left.send(&payload).expect("send bounded packet");
    assert_eq!(
        right
            .receive(4096, 0)
            .expect("receive bounded packet")
            .payload(),
        payload
    );
}

#[test]
fn close_is_idempotent_and_rejects_later_capacity_changes() {
    let (mut socket, _sender) = pair();
    let peer_pid = socket.peer().initial_info().pid();

    socket.close();
    socket.close();

    assert!(matches!(socket.as_fd(), Err(SeqpacketError::Closed)));
    assert!(matches!(
        socket.provision_packet_capacity(4096),
        Err(SeqpacketError::Closed)
    ));
    assert_eq!(socket.peer().initial_info().pid(), peer_pid);
}

#[test]
fn cached_peer_remains_distinct_from_a_delegated_response_subject() {
    let listener = uapi::seqpacket_listener().expect("create listener");
    let (mut connector, control, delegated) = spawn_connector(listener.as_fd());
    let connector_pid = connector.pid();
    let accepted = uapi::accept_record_subject_socket(listener.as_fd()).expect("accept connector");
    let mut receiver =
        DescriptorSubjectSocket::from_owned(accepted).expect("configure accepted channel");

    assert_eq!(receiver.peer().initial_info().pid(), connector_pid);
    uapi::send_seqpacket(delegated.as_fd(), b"delegated writer")
        .expect("send from delegated writer");
    let record = receiver.receive(64, 0).expect("receive delegated record");
    assert_eq!(record.payload(), b"delegated writer");
    assert_eq!(record.subject().initial_info().pid(), std::process::id());
    assert_ne!(record.subject().initial_info().pid(), connector_pid);
    assert_eq!(receiver.peer().initial_info().pid(), connector_pid);

    finish_connector(&mut connector, control.as_fd());
}

#[test]
fn descriptor_sender_connect_rejects_noncanonical_paths_before_connecting() {
    for path in [
        "relative.sock",
        "/run/../socket",
        "/run/./socket",
        "/run/socket/.",
        "/run//socket",
        "/run/socket/",
        "/run/socket\0tail",
    ] {
        assert!(matches!(
            DescriptorSubjectSocket::connect(Path::new(path)),
            Err(SeqpacketError::Kernel(crate::Error::InvalidInput {
                field: "descriptor-subject connection path",
                ..
            }))
        ));
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
    for count in 0..=6 {
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

#[test]
fn mount_scope_reply_profile_accepts_only_zero_or_five_descriptors() {
    for count in 0..=6 {
        let (mut receiver, sender) = pair();
        let file = tempfile::tempfile().expect("transferred file");
        if count == 0 {
            uapi::send_seqpacket(sender.as_fd(), b"reply").expect("no-rights reply");
        } else {
            uapi::send_seqpacket_rights(sender.as_fd(), b"reply", &vec![file.as_fd(); count])
                .expect("rights reply");
        }
        let result = receiver.receive_mount_scope_reply(64);
        if count == 0 || count == 5 {
            let record = result.expect("valid mount-scope descriptor count");
            assert_eq!(record.descriptors().len(), count);
            assert_eq!(record.subject().initial_info().pid(), std::process::id());
            for descriptor in record.descriptors() {
                assert!(uapi::is_cloexec(descriptor.as_fd()).expect("transferred CLOEXEC"));
            }
        } else {
            assert!(result.is_err(), "unexpected descriptor count {count}");
            assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
        }
    }
}

#[test]
fn mount_scope_reply_bounds_leave_the_record_queued_but_oversize_closes() {
    let (mut receiver, sender) = pair();
    let file = tempfile::tempfile().expect("transferred file");
    uapi::send_seqpacket_rights(sender.as_fd(), b"reply", &[file.as_fd(); 5])
        .expect("mount-scope reply");
    for maximum in [0, MAXIMUM_PACKET_BYTES + 1] {
        assert!(matches!(
            receiver.receive_mount_scope_reply(maximum),
            Err(SeqpacketError::InvalidMaximum)
        ));
    }
    assert!(matches!(
        receiver.receive_mount_scope_reply(4),
        Err(SeqpacketError::RecordTooLarge { .. })
    ));
    assert!(matches!(receiver.as_fd(), Err(SeqpacketError::Closed)));
}

#[test]
fn mount_scope_reply_preserves_order_and_owns_descriptors_after_sender_closes() {
    let (mut receiver, sender) = pair();
    let files: Vec<_> = (0..5)
        .map(|_| tempfile::tempfile().expect("distinct transferred file"))
        .collect();
    let identities: Vec<_> = files
        .iter()
        .map(|file| {
            let metadata = file.metadata().expect("sender identity");
            (metadata.dev(), metadata.ino())
        })
        .collect();
    let descriptors: Vec<_> = files.iter().map(AsFd::as_fd).collect();
    uapi::send_seqpacket_rights(sender.as_fd(), b"reply", &descriptors).expect("mount-scope reply");
    drop(descriptors);
    drop(files);
    drop(sender);

    let record = receiver
        .receive_mount_scope_reply(64)
        .expect("queued reply");
    let (payload, subject, descriptors) = record.into_parts();
    assert_eq!(payload, b"reply");
    assert_eq!(subject.initial_info().pid(), std::process::id());
    let received: Vec<_> = descriptors
        .into_iter()
        .map(|descriptor| {
            let metadata = std::fs::File::from(descriptor)
                .metadata()
                .expect("retained receiver identity");
            (metadata.dev(), metadata.ino())
        })
        .collect();
    assert_eq!(received, identities);
}
