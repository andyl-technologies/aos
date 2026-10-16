//! Exercises real Linux packet and ancillary custody independently of publication.

use super::super::wire::Operation;
use super::*;
use std::io::Write;
use terrane_core::identity::TERRANE_V1;

fn policy() -> ValidationPolicy<'static> {
    ValidationPolicy {
        domain: "fixture",
        identity: &TERRANE_V1,
        chunk_profile: "fixture",
    }
}

fn packet() -> Packet {
    Packet {
        version: 1,
        request_id: 1,
        operation: Operation::Drain as i32,
        domain: "fixture".into(),
        cache_incarnation: vec![1; 16],
        wait_budget_ms: 100,
        ..Packet::default()
    }
}

fn pair() -> (Connection, Connection) {
    let (a, b) = net::socketpair(
        AddressFamily::UNIX,
        SocketType::SEQPACKET,
        SocketFlags::CLOEXEC,
        None,
    )
    .unwrap();
    (
        Connection {
            descriptor: a,
            receives_responses: true,
            active: Mutex::new(BTreeMap::new()),
        },
        Connection {
            descriptor: b,
            receives_responses: false,
            active: Mutex::new(BTreeMap::new()),
        },
    )
}

fn raw_send(connection: &Connection, bytes: &[u8], descriptors: &[BorrowedFd<'_>]) {
    let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(253))];
    let mut ancillary = net::SendAncillaryBuffer::new(&mut space);
    if !descriptors.is_empty() {
        assert!(ancillary.push(net::SendAncillaryMessage::ScmRights(descriptors)));
    }
    net::sendmsg(
        &connection.descriptor,
        &[IoSlice::new(bytes)],
        &mut ancillary,
        net::SendFlags::NOSIGNAL,
    )
    .unwrap();
}

#[test]
fn kernel_peer_credentials_cannot_be_claimed_in_packet() {
    let (a, _) = pair();
    let actual = rustix::process::geteuid().as_raw();
    assert!(authenticate(&a.descriptor, actual).is_ok());
    assert!(matches!(
        authenticate(&a.descriptor, actual.wrapping_add(1)),
        Err(Error::Denied)
    ));
}

#[test]
fn real_seqpacket_roundtrip_requires_response_correlation() {
    let (client, server) = pair();
    client.send(&packet(), &[], &policy()).unwrap();
    let received = server.receive(&policy()).unwrap();
    assert_eq!(received.packet, packet());
    let response = Packet {
        response: true,
        wait_budget_ms: 0,
        ..packet()
    };
    server.send(&response, &[], &policy()).unwrap();
    assert_eq!(client.receive(&policy()).unwrap().packet, response);
    assert!(server.send(&response, &[], &policy()).is_err());
}

#[test]
fn duplicate_active_request_is_rejected_before_dispatch() {
    let (client, server) = pair();
    client.send(&packet(), &[], &policy()).unwrap();
    server.receive(&policy()).unwrap();
    assert!(client.send(&packet(), &[], &policy()).is_err());
    raw_send(&client, &packet().encode_to_vec(), &[]);
    assert!(server.receive(&policy()).is_err());
}

#[test]
fn unsolicited_and_mismatched_responses_are_rejected() {
    let (client, server) = pair();
    let response = Packet {
        response: true,
        wait_budget_ms: 0,
        ..packet()
    };
    raw_send(&server, &response.encode_to_vec(), &[]);
    assert!(client.receive(&policy()).is_err());

    client.send(&packet(), &[], &policy()).unwrap();
    server.receive(&policy()).unwrap();
    let wrong = Packet {
        cache_incarnation: vec![2; 16],
        ..response
    };
    raw_send(&server, &wrong.encode_to_vec(), &[]);
    assert!(client.receive(&policy()).is_err());
}

#[test]
fn oversized_payload_and_excess_rights_are_rejected() {
    let (client, server) = pair();
    raw_send(&client, &vec![1; MAX_PACKET + 1], &[]);
    assert!(server.receive(&policy()).is_err());

    let file = File::open("/dev/null").unwrap();
    raw_send(
        &client,
        &packet().encode_to_vec(),
        &[file.as_fd(), file.as_fd(), file.as_fd()],
    );
    assert!(server.receive(&policy()).is_err());
}

#[test]
fn received_rights_are_close_on_exec_and_writable_sources_fail() {
    let (client, server) = pair();
    let path = std::env::temp_dir().join(format!("publisher-local-source-{}", std::process::id()));
    let mut writer = File::create_new(&path).unwrap();
    writer.write_all(b"source").unwrap();
    let reader = File::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();

    raw_send(&client, b"x", &[reader.as_fd()]);
    let (_, received) = receive_record(&server.descriptor).unwrap();
    assert_eq!(received.len(), 1);
    assert!(
        rustix::io::fcntl_getfd(&received[0])
            .unwrap()
            .contains(rustix::io::FdFlags::CLOEXEC)
    );
    assert!(validate_source(&received[0]).is_ok());
    assert!(validate_source(&writer).is_err());
    assert!(validate_source(File::open("/dev/null").unwrap()).is_err());
}

#[test]
fn rejected_rights_do_not_accumulate_descriptors() {
    let (client, server) = pair();
    use std::os::unix::fs::MetadataExt;
    let path = std::env::temp_dir().join(format!("publisher-local-leak-{}", std::process::id()));
    drop(File::create_new(&path).unwrap());
    let file = File::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let identity = file.metadata().unwrap();
    let count = || {
        std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| std::fs::metadata(entry.path()).ok())
            .filter(|metadata| metadata.dev() == identity.dev() && metadata.ino() == identity.ino())
            .count()
    };
    let before = count();
    for _ in 0..128 {
        raw_send(&client, b"invalid", &[file.as_fd(), file.as_fd()]);
        assert!(server.receive(&policy()).is_err());
    }
    assert_eq!(count(), before);
}

#[test]
fn ancillary_truncation_and_unregistered_credentials_are_rejected() {
    let (client, server) = pair();
    let file = File::open("/dev/null").unwrap();
    raw_send(&client, b"x", &[file.as_fd(), file.as_fd()]);
    assert!(receive_record_with_space::<1>(&server.descriptor).is_err());

    net::sockopt::set_socket_passcred(&server.descriptor, true).unwrap();
    raw_send(&client, &packet().encode_to_vec(), &[]);
    assert!(server.receive(&policy()).is_err());
}
