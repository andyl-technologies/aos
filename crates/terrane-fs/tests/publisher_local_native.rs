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
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::Arc,
    thread,
    time::Duration,
};

use rustix::{
    fs::chown,
    process::{Gid, Uid},
};
use terrane::{
    domain::DomainBinding,
    host::{
        cache::DomainHostLayout,
        publication::{PublicationClaim, PublicationRecipe},
    },
};
use terrane_core::{
    chunking::ChunkProfile,
    identity::{Descriptor, IdentityKind, TERRANE_V1},
};
use terrane_fs::{
    host_cache::NativeHostLayout,
    publisher_io::{
        NativePublicationWorker, NativePublisherConfig, NativeRetirementPolicy, NativeWipePolicy,
    },
    publisher_local::{
        client::{Client, ClientConfig},
        server::{DomainPublisher, Server, ServerConfig},
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
    let selected = ValidationPolicy {
        domain: &request.domain,
        identity: &TERRANE_V1,
        chunk_profile: "cdc-1m",
    };
    connection.send(request, &files, &selected).unwrap();
    connection.receive(&selected).unwrap()
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
    // The VM supplies source-built util-linux. Set explicit supplementary
    // groups without unsafe process hooks or changing the primary role group.
    Running(
        Command::new("setpriv")
            .args([
                format!("--reuid={uid}"),
                format!("--regid={uid}"),
                format!("--groups={SERVE}"),
                "--".into(),
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "publisher_local_native_role",
                "--ignored",
                "--nocapture",
            ])
            .env("TERRANE_PUBLISHER_NATIVE_ROLE", role)
            .env("TERRANE_PUBLISHER_NATIVE_ROOT", root)
            .spawn()
            .unwrap(),
    )
}

fn create_layout(path: &Path) {
    fs::create_dir(path).unwrap();
    chown(
        path,
        Some(Uid::from_raw(PUBLISH)),
        Some(Gid::from_raw(SERVE)),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o2750)).unwrap();
    for (name, shared) in [
        ("state", false),
        ("chunks", true),
        ("objects", true),
        ("quarantine", true),
        ("sealed", false),
        ("staging", false),
        ("pending-delete", false),
        ("state/publication", false),
    ] {
        let directory = path.join(name);
        fs::create_dir(&directory).unwrap();
        let uid = if shared { SERVE } else { PUBLISH };
        chown(
            &directory,
            Some(Uid::from_raw(uid)),
            Some(Gid::from_raw(SERVE)),
        )
        .unwrap();
        let mode = if shared {
            0o2770
        } else if name == "state" {
            0o750
        } else {
            0o700
        };
        fs::set_permissions(directory, fs::Permissions::from_mode(mode)).unwrap();
    }
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
    create_layout(&scratch.0.join("public"));
    create_layout(&scratch.0.join("private"));
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
            let mut domains = Vec::new();
            for (name, label, seed) in [("public", "public", 0), ("private", "private:fixture", 1)]
            {
                let worker = NativePublicationWorker::start(NativePublisherConfig {
                    domain: label.into(),
                    layout_root: root.join(name),
                    wipe: NativeWipePolicy::None,
                    retirement: NativeRetirementPolicy::new(Duration::from_millis(100)).unwrap(),
                    content_uid: SERVE,
                    content_gid: SERVE,
                })
                .unwrap();
                domains.push(DomainPublisher {
                    domain: label.into(),
                    chunk_profile_name: "cdc-1m".into(),
                    chunk_profile: ChunkProfile::cdc_1m([seed; 32]),
                    worker,
                });
            }
            let server = Server::bind(
                ServerConfig {
                    socket_path: root.join("publisher.sock"),
                    identities: identities(),
                    max_connections: 4,
                },
                domains,
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

fn private_domain(mut packet: Packet) -> Packet {
    packet.domain = "private:fixture".into();
    packet
}

fn check_other_domain(
    connection: &Connection,
    source: &File,
    device: u64,
    public_inode: u64,
    public_token: &[u8],
) -> (u64, Vec<u8>) {
    complete(
        connection,
        &private_domain(packet(Operation::Drain, 100, 1)),
    );
    let missing = exchange(
        connection,
        &private_domain(publication(Operation::Adopt, 101, 1)),
        None,
    );
    assert_eq!(
        missing.packet.result, 3,
        "another domain must not supply fallback content"
    );
    complete(
        connection,
        &private_domain(packet(Operation::Resume, 102, 1)),
    );
    let published = backing(
        exchange(
            connection,
            &private_domain(publication(Operation::Publish, 103, 1)),
            Some(source),
        ),
        device,
    );
    assert_ne!(published.0, public_inode);
    assert_ne!(published.1, public_token);
    let wrong = private_domain(Packet {
        body: publication(Operation::Publish, 1, 1).body,
        body_incarnation: public_token.to_vec(),
        ..packet(Operation::Retire, 104, 1)
    });
    assert_ne!(exchange(connection, &wrong, None).packet.result, 0);
    assert_eq!(
        backing(
            exchange(
                connection,
                &private_domain(publication(Operation::Adopt, 105, 1)),
                None
            ),
            device
        ),
        published
    );
    published
}

fn check_unknown_domain(root: &Path) {
    let connection = Connection::connect(&root.join("publisher.sock"), identities()).unwrap();
    let mut unknown = packet(Operation::Probe, 900, 1);
    unknown.domain = "unknown".into();
    let policy = ValidationPolicy {
        domain: "unknown",
        identity: &TERRANE_V1,
        chunk_profile: "cdc-1m",
    };
    connection.send(&unknown, &[], &policy).unwrap();
    assert!(
        connection.receive(&policy).is_err(),
        "unknown domain must never select a worker"
    );
}

fn pending_token(
    connection: &Connection,
    body: Option<BodyKey>,
    request_id: u64,
    incarnation: u8,
) -> Vec<u8> {
    let response = exchange(
        connection,
        &Packet {
            body,
            ..packet(Operation::InspectPending, request_id, incarnation)
        },
        None,
    );
    assert_eq!(response.packet.result, 0);
    assert!(response.files.is_empty());
    assert_eq!(response.packet.verity_algorithm, 0);
    assert!(response.packet.verity_digest.is_empty());
    assert_eq!(response.packet.body_incarnation.len(), 32);
    response.packet.body_incarnation
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

    let private = check_other_domain(&connection, &source, expected_device, inode, &token);
    check_unknown_domain(root);

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
    assert_eq!(
        backing(
            exchange(
                &connection,
                &private_domain(publication(Operation::Adopt, 106, 1)),
                None
            ),
            expected_device
        ),
        private
    );

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
    complete(&connection, &packet(Operation::Drain, 18, 3));
    let absent = exchange(&connection, &publication(Operation::Adopt, 19, 3), None);
    assert_eq!(absent.packet.result, 3);
    assert!(absent.files.is_empty());
    let stale_restore = Packet {
        body: body.clone(),
        body_incarnation: recovered.1,
        ..packet(Operation::Restore, 20, 3)
    };
    assert_ne!(exchange(&connection, &stale_restore, None).packet.result, 0);
    let pending = pending_token(&connection, body.clone(), 21, 3);
    complete(
        &connection,
        &Packet {
            body: body.clone(),
            body_incarnation: pending.clone(),
            ..packet(Operation::Restore, 22, 3)
        },
    );
    // Restored namespace custody alone gave no descriptor. Canonical adoption
    // independently verifies plaintext and seal before returning this handle.
    assert_eq!(
        backing(
            exchange(&connection, &publication(Operation::Adopt, 23, 3), None),
            expected_device
        ),
        (inode, pending.clone())
    );
    complete(&connection, &packet(Operation::Resume, 24, 3));
    complete(
        &connection,
        &Packet {
            body: body.clone(),
            body_incarnation: pending,
            ..packet(Operation::Retire, 25, 3)
        },
    );
    complete(&connection, &packet(Operation::Drain, 26, 4));
    let pending = pending_token(&connection, body.clone(), 27, 4);
    for attempt in 0..100 {
        let response = exchange(
            &connection,
            &Packet {
                body: body.clone(),
                body_incarnation: pending.clone(),
                ..packet(Operation::FinishRetirement, 28 + attempt, 4)
            },
            None,
        );
        if response.packet.result == 0 {
            break;
        }
        assert_eq!(
            response.packet.result, 7,
            "only an actual unexpired lease may delay removal"
        );
        assert!(attempt < 99, "retirement lease did not expire");
        thread::sleep(Duration::from_millis(10));
    }
    let removed = exchange(&connection, &publication(Operation::Adopt, 200, 4), None);
    assert_eq!(removed.packet.result, 3);
    assert!(removed.files.is_empty());

    complete(&connection, &packet(Operation::Resume, 201, 4));
    let (recreated_inode, _) = backing(
        exchange(
            &connection,
            &publication(Operation::Publish, 202, 4),
            Some(&source),
        ),
        expected_device,
    );
    check_authenticated_client(root, recreated_inode);
}

fn check_authenticated_client(root: &Path, expected_inode: u64) {
    let identity = TERRANE_V1
        .calculate(IdentityKind::Chunk, PLAINTEXT)
        .unwrap();
    let descriptor = Descriptor::from_identity(&TERRANE_V1, &identity, PLAINTEXT).unwrap();
    let layout = Arc::new(
        NativeHostLayout::inspect(
            DomainHostLayout::new(
                root.join("public"),
                DomainBinding {
                    domain: "public".into(),
                    reference: "fixture".into(),
                    root: identity,
                    path: b"/".to_vec(),
                },
                ChunkProfile::cdc_1m([0; 32]),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let client = Client::connect(
        ClientConfig {
            socket_path: root.join("publisher.sock"),
            identities: identities(),
            chunk_profile_name: "cdc-1m".into(),
            wait_budget_ms: 10_000,
        },
        layout.clone(),
    )
    .unwrap();
    assert!(
        client.probe().is_err(),
        "a new client requires actual drain custody"
    );
    client.drain().unwrap();
    let probe = client.probe().unwrap();
    assert!(Arc::ptr_eq(probe.layout(), &layout));
    assert_eq!(probe.handle().metadata().unwrap().nlink(), 0);
    assert_eq!(probe.handle().metadata().unwrap().len(), 0);
    assert_eq!(
        verity::measure(probe.handle()).unwrap().digest,
        probe.binding().digest
    );

    let claim = PublicationClaim::new(
        "public".into(),
        PublicationRecipe::Inline {
            chunk: descriptor.clone(),
        },
        layout.layout().chunk_profile(),
    )
    .unwrap();
    let adopted = client.adopt_inline(claim).unwrap();
    assert!(Arc::ptr_eq(adopted.layout(), &layout));
    assert_eq!(adopted.handle().metadata().unwrap().ino(), expected_inode);
    assert_eq!(adopted.claim().descriptor(), &descriptor);
    assert_eq!(
        verity::measure(adopted.handle()).unwrap().digest,
        adopted.binding().digest
    );
    assert_eq!(adopted.incarnation().len(), 32);

    drop(client);
    drop(layout);
    // The receipt itself still owns the real root guard and measured inode.
    adopted.layout().recheck().unwrap();
    let mut plaintext = Vec::new();
    (&*adopted.handle()).read_to_end(&mut plaintext).unwrap();
    assert_eq!(plaintext, PLAINTEXT);
}
