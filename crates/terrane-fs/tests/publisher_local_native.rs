//! Exercises the concrete native owner through authenticated role-process sockets.
//!
//! Requires a dedicated disk-backed, verity-enabled ext4 VM mount. These tests
//! establish local native effects; service network and capability policy have
//! separate qualification.

#![cfg(feature = "tokio")]

use std::{
    fs::{self, File},
    io::Read,
    os::{
        fd::AsFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::Duration,
};

use rustix::{
    fs::chown,
    process::{Gid, Uid},
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{Descriptor, IdentityKind, TERRANE_V1},
};
use terrane_fs::{
    publisher_io::NativePublicationWorker,
    publisher_local::{
        server::{Server, ServerConfig},
        socket::{Connection, ReceivedPacket, RoleIdentities},
        validation::ValidationPolicy,
        wire::{BodyKey, BodyKind, Claim, Operation, Packet},
    },
    verity,
};

const SERVE: u32 = 61001;
const PUBLISH: u32 = 61002;
const PLAINTEXT: &[u8] = b"native publisher-local immutable fixture";

fn identities() -> RoleIdentities {
    RoleIdentities {
        serve_uid: SERVE,
        publish_uid: PUBLISH,
    }
}

fn policy() -> ValidationPolicy<'static> {
    ValidationPolicy {
        domain: "public",
        identity: &TERRANE_V1,
        chunk_profile: "cdc-1m",
    }
}

fn packet(operation: Operation, request_id: u64, incarnation: u8) -> Packet {
    Packet {
        version: 1,
        request_id,
        operation: operation as i32,
        domain: "public".into(),
        cache_incarnation: vec![incarnation; 16],
        wait_budget_ms: 10_000,
        ..Packet::default()
    }
}

fn publication(operation: Operation, request_id: u64, incarnation: u8) -> Packet {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, PLAINTEXT)
        .unwrap();
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, PLAINTEXT)
        .unwrap()
        .encode();
    Packet {
        claim: Some(Claim {
            descriptor: descriptor.clone(),
            chunk_profile: "cdc-1m".into(),
            plaintext_size: PLAINTEXT.len() as u64,
            ..Claim::default()
        }),
        body: Some(BodyKey {
            kind: BodyKind::Sealed as i32,
            descriptor,
            ..BodyKey::default()
        }),
        ..packet(operation, request_id, incarnation)
    }
}

fn exchange(connection: &Connection, request: &Packet, source: Option<&File>) -> ReceivedPacket {
    let files = source.iter().map(|file| file.as_fd()).collect::<Vec<_>>();
    connection.send(request, &files, &policy()).unwrap();
    connection.receive(&policy()).unwrap()
}

fn complete(connection: &Connection, request: &Packet) {
    let response = exchange(connection, request, None);
    assert_eq!(response.packet.result, 0);
    assert!(response.files.is_empty());
    assert!(response.packet.body_incarnation.is_empty());
}

fn backing(mut response: ReceivedPacket, expected_device: u64) -> (u64, Vec<u8>) {
    assert_eq!(response.packet.result, 0);
    assert_eq!(response.files.len(), 1);
    let mut file = response.files.remove(0);
    let metadata = file.metadata().unwrap();
    assert_eq!(metadata.dev(), expected_device);
    let binding = verity::measure(&file).unwrap();
    assert_eq!(
        u32::from(binding.algorithm),
        response.packet.verity_algorithm
    );
    assert_eq!(binding.digest, response.packet.verity_digest);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, PLAINTEXT);
    (metadata.ino(), response.packet.body_incarnation)
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(role: &str, uid: u32, root: &Path) -> Running {
    Running(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "publisher_local_native_role",
                "--ignored",
                "--nocapture",
            ])
            .env("TERRANE_PUBLISHER_NATIVE_ROLE", role)
            .env("TERRANE_PUBLISHER_NATIVE_ROOT", root)
            .uid(uid)
            .gid(uid)
            .spawn()
            .unwrap(),
    )
}

#[test]
#[ignore = "requires dedicated verity-enabled ext4 and distinct VM role identities"]
fn publisher_local_native_lifecycle_vm() {
    assert_eq!(std::env::var("TERRANE_PUBLISHER_VM").as_deref(), Ok("1"));
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let base = PathBuf::from(std::env::var_os("TERRANE_PUBLISHER_EXT4_ROOT").unwrap());
    let scratch = Scratch(base.join(format!("publisher-local-native-{}", std::process::id())));
    fs::create_dir(&scratch.0).unwrap();
    chown(
        &scratch.0,
        Some(Uid::from_raw(PUBLISH)),
        Some(Gid::from_raw(SERVE)),
    )
    .unwrap();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o2750)).unwrap();
    for name in ["sealed", "staging", "pending", "state", "quarantine"] {
        let path = scratch.0.join(name);
        fs::create_dir(&path).unwrap();
        chown(
            &path,
            Some(Uid::from_raw(PUBLISH)),
            Some(Gid::from_raw(PUBLISH)),
        )
        .unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(scratch.0.join("source"), PLAINTEXT).unwrap();
    fs::set_permissions(scratch.0.join("source"), fs::Permissions::from_mode(0o444)).unwrap();

    let _publisher = spawn("publisher", PUBLISH, &scratch.0);
    for attempt in 0..1000 {
        if scratch.0.join("ready").exists() {
            break;
        }
        assert!(attempt < 999, "native publisher did not bind");
        thread::sleep(Duration::from_millis(10));
    }
    let mut serve = spawn("serve", SERVE, &scratch.0);
    assert!(serve.0.wait().unwrap().success());
}

#[test]
#[ignore = "native role subprocess, invoked by publisher_local_native_lifecycle_vm"]
fn publisher_local_native_role() {
    assert_eq!(std::env::var("TERRANE_PUBLISHER_VM").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("TERRANE_PUBLISHER_NATIVE_ROOT").unwrap());
    match std::env::var("TERRANE_PUBLISHER_NATIVE_ROLE")
        .unwrap()
        .as_str()
    {
        "publisher" => {
            let worker = NativePublicationWorker::start(
                "public".into(),
                &root.join("sealed"),
                &root.join("staging"),
                &root.join("pending"),
                &root.join("state"),
            )
            .unwrap();
            let server = Server::bind(
                ServerConfig {
                    socket_path: root.join("publisher.sock"),
                    identities: identities(),
                    domain: "public".into(),
                    chunk_profile_name: "cdc-1m".into(),
                    chunk_profile: ChunkProfile::cdc_1m([0; 32]),
                    max_connections: 4,
                },
                worker,
            )
            .unwrap();
            let metadata = fs::metadata(root.join("publisher.sock")).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o660);
            assert_eq!(metadata.gid(), SERVE);
            fs::write(root.join("ready"), b"ready").unwrap();
            server.run().unwrap();
        }
        "serve" => run_client(&root),
        role => panic!("unknown native role {role}"),
    }
}

fn run_client(root: &Path) {
    let connection = Connection::connect(&root.join("publisher.sock"), identities()).unwrap();
    let expected_device = fs::metadata(root).unwrap().dev();
    complete(&connection, &packet(Operation::Drain, 1, 1));
    let mut probe = exchange(&connection, &packet(Operation::Probe, 2, 1), None);
    assert_eq!(probe.packet.result, 0);
    let file = probe.files.remove(0);
    assert_eq!(file.metadata().unwrap().dev(), expected_device);
    assert_eq!(
        verity::measure(&file).unwrap().digest,
        probe.packet.verity_digest
    );
    assert_eq!(file.metadata().unwrap().len(), 0);

    // The fixture starts with genuinely empty private roots and no cache
    // metadata or pins. This does not model nonempty cache reconciliation.
    complete(&connection, &packet(Operation::Resume, 3, 1));
    let source = File::open(root.join("source")).unwrap();
    let first = publication(Operation::Publish, 4, 1);
    let (inode, token) = backing(
        exchange(&connection, &first, Some(&source)),
        expected_device,
    );
    assert_eq!(token.len(), 32);
    let repeated = publication(Operation::Publish, 5, 1);
    let (same_inode, same_token) = backing(
        exchange(&connection, &repeated, Some(&source)),
        expected_device,
    );
    assert_eq!((same_inode, same_token), (inode, token.clone()));
    let inspected = publication(Operation::InspectBody, 6, 1);
    assert_eq!(
        backing(exchange(&connection, &inspected, None), expected_device),
        (inode, token.clone())
    );

    let body = first.body.clone();
    let wrong = Packet {
        body: body.clone(),
        body_incarnation: vec![0; 32],
        ..packet(Operation::Retire, 7, 1)
    };
    let rejected = exchange(&connection, &wrong, None);
    assert_ne!(rejected.packet.result, 0);
    assert!(rejected.files.is_empty());
    let retire = Packet {
        body: body.clone(),
        body_incarnation: token.clone(),
        ..packet(Operation::Retire, 8, 1)
    };
    complete(&connection, &retire);
    let restore = Packet {
        body: body.clone(),
        body_incarnation: token.clone(),
        ..packet(Operation::Restore, 9, 1)
    };
    complete(&connection, &restore);
    assert_eq!(
        backing(
            exchange(&connection, &publication(Operation::Adopt, 10, 1), None),
            expected_device
        ),
        (inode, token.clone())
    );

    complete(&connection, &packet(Operation::Drain, 11, 2));
    assert_ne!(
        exchange(&connection, &packet(Operation::Probe, 12, 1), None)
            .packet
            .result,
        0
    );
    let recovered = backing(
        exchange(&connection, &publication(Operation::Adopt, 13, 2), None),
        expected_device,
    );
    assert_eq!(recovered.0, inode);
    assert_ne!(recovered.1, token);
    let blocked = Packet {
        body: body.clone(),
        body_incarnation: recovered.1.clone(),
        ..packet(Operation::Retire, 14, 2)
    };
    assert_ne!(exchange(&connection, &blocked, None).packet.result, 0);
    complete(&connection, &packet(Operation::Resume, 15, 2));
    let stale = Packet {
        body: body.clone(),
        body_incarnation: token,
        ..packet(Operation::Retire, 16, 2)
    };
    assert_ne!(exchange(&connection, &stale, None).packet.result, 0);
    complete(
        &connection,
        &Packet {
            body: body.clone(),
            body_incarnation: recovered.1.clone(),
            ..packet(Operation::Retire, 17, 2)
        },
    );
    complete(
        &connection,
        &Packet {
            body,
            body_incarnation: recovered.1,
            ..packet(Operation::FinishRetirement, 18, 2)
        },
    );
    let removed = exchange(&connection, &publication(Operation::Adopt, 19, 2), None);
    assert_ne!(removed.packet.result, 0);
    assert!(removed.files.is_empty());
}
