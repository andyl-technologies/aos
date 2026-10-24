//! Exercises real Linux packet and ancillary custody independently of publication.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::super::wire::Operation;
use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use terrane_format::identity::TERRANE_V1;

struct SocketModeFixture {
    path: std::path::PathBuf,
    parent: OwnedFd,
    node: OwnedFd,
    _socket: OwnedFd,
}

impl SocketModeFixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "publisher-local-mode-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o2700)).unwrap();
        let parent = rustix::fs::open(
            &directory,
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let path = directory.join("publisher.sock");
        let socket = new_socket().unwrap();
        net::bind(&socket, &net::SocketAddrUnix::new(&path).unwrap()).unwrap();
        // Fixture setup uses its private pathname; the production operation
        // below must change the retained inode without a pathname chmod.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let node = rustix::fs::openat(
            &parent,
            "publisher.sock",
            OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        Self {
            path,
            parent,
            node,
            _socket: socket,
        }
    }
}

impl Drop for SocketModeFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(self.path.parent().unwrap()).unwrap();
    }
}

// Exact directory modes require the real ext4 native fixture. The package's
// user namespace cannot supply every builder filesystem's setgid operations.
#[cfg_attr(
    not(feature = "native-test-fixtures"),
    ignore = "requires the ext4 native fixture for exact setgid directory modes"
)]
#[test]
fn retained_socket_chmod_sets_exact_mode_without_changing_inode_or_group() {
    let fixture = SocketModeFixture::new();
    let before = rustix::fs::fstat(&fixture.node).unwrap();
    assert_eq!(before.st_mode & 0o7777, 0o600);

    set_bound_socket_mode(
        &fixture.parent,
        OsStr::new("publisher.sock"),
        &fixture.node,
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();

    let retained = rustix::fs::fstat(&fixture.node).unwrap();
    let named =
        rustix::fs::statat(&fixture.parent, "publisher.sock", AtFlags::SYMLINK_NOFOLLOW).unwrap();
    for actual in [retained, named] {
        assert_eq!(
            (actual.st_dev, actual.st_ino),
            (before.st_dev, before.st_ino)
        );
        assert_eq!(
            (actual.st_uid, actual.st_gid),
            (before.st_uid, before.st_gid)
        );
        assert_eq!(actual.st_mode & 0o7777, 0o660);
        assert_eq!(
            rustix::fs::FileType::from_raw_mode(actual.st_mode),
            rustix::fs::FileType::Socket
        );
    }
}

#[cfg_attr(
    not(feature = "native-test-fixtures"),
    ignore = "requires the ext4 native fixture for exact setgid directory modes"
)]
#[test]
fn replaced_socket_name_is_rejected_without_changing_either_inode() {
    let fixture = SocketModeFixture::new();
    let retained_before = rustix::fs::fstat(&fixture.node).unwrap();
    std::fs::rename(&fixture.path, fixture.path.with_file_name("original.sock")).unwrap();
    File::create(&fixture.path).unwrap();
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o400)).unwrap();

    assert!(
        set_bound_socket_mode(
            &fixture.parent,
            OsStr::new("publisher.sock"),
            &fixture.node,
            rustix::process::geteuid().as_raw(),
        )
        .is_err()
    );

    let retained = rustix::fs::fstat(&fixture.node).unwrap();
    assert_eq!(
        (retained.st_dev, retained.st_ino),
        (retained_before.st_dev, retained_before.st_ino)
    );
    assert_eq!(retained.st_mode & 0o7777, 0o600);
    assert_eq!(
        std::fs::metadata(&fixture.path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o400
    );
}

#[cfg_attr(
    not(feature = "native-test-fixtures"),
    ignore = "requires the ext4 native fixture for exact setgid directory modes"
)]
#[test]
fn socket_chmod_rejects_wrong_type_and_owner_before_mutation() {
    let fixture = SocketModeFixture::new();
    let regular = fixture.path.with_file_name("regular");
    File::create(&regular).unwrap();
    std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o400)).unwrap();
    let regular_node = rustix::fs::openat(
        &fixture.parent,
        "regular",
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let uid = rustix::process::geteuid().as_raw();

    assert!(
        set_bound_socket_mode(&fixture.parent, OsStr::new("regular"), &regular_node, uid).is_err()
    );
    assert!(
        set_bound_socket_mode(
            &fixture.parent,
            OsStr::new("publisher.sock"),
            &fixture.node,
            uid.wrapping_add(1),
        )
        .is_err()
    );

    assert_eq!(
        rustix::fs::fstat(&regular_node).unwrap().st_mode & 0o7777,
        0o400
    );
    assert_eq!(
        rustix::fs::fstat(&fixture.node).unwrap().st_mode & 0o7777,
        0o600
    );
}

fn policy() -> ValidationPolicy<'static> {
    ValidationPolicy {
        domain: "public",
        identity: &TERRANE_V1,
        chunk_profile: "cdc-1m",
    }
}

fn packet() -> Packet {
    Packet {
        version: 1,
        request_id: 1,
        operation: Operation::Drain as i32,
        domain: "public".into(),
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

#[test]
fn configured_domain_selection_has_no_fallback() {
    let (client, server) = pair();
    let other = ValidationPolicy {
        domain: "private:other",
        identity: &TERRANE_V1,
        chunk_profile: "cdc-1m",
    };
    let request = Packet {
        domain: "private:other".into(),
        ..packet()
    };
    client.send(&request, &[], &other).unwrap();
    let policies = [policy(), other];
    assert_eq!(
        server.receive_selected(&policies).unwrap().packet.domain,
        "private:other"
    );

    let denied = Packet {
        request_id: 2,
        domain: "private:unknown".into(),
        ..packet()
    };
    let unknown = ValidationPolicy {
        domain: "private:unknown",
        identity: &TERRANE_V1,
        chunk_profile: "cdc-1m",
    };
    client.send(&denied, &[], &unknown).unwrap();
    assert!(matches!(
        server.receive_selected(&policies),
        Err(Error::Denied)
    ));
}
