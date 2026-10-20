//! Runs real, distinct UID role processes in the dedicated Linux VM fixture.
//!
//! These ignored tests require an explicit VM marker and root. They establish
//! local socket authentication and directory custody, not network sandboxing
//! or completion of publication commands.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use rustix::{
    fs::chown,
    net::{self, AddressFamily, SocketFlags, SocketType},
    process::{Gid, Uid},
};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::Duration,
};
use terrane_format::identity::TERRANE_V1;
use terrane_linux::publisher_local::{
    Error,
    socket::{Connection, Listener, RoleIdentities},
    validation::ValidationPolicy,
    wire::{Operation, Packet},
};

const SERVE: u32 = 61001;
const PUBLISH: u32 = 61002;
const OUTSIDER: u32 = 61003;
const OTHER_ROLES: [(&str, u32); 4] = [
    ("realize", 61004),
    ("gc", 61005),
    ("worker", 61006),
    ("sandbox", 61007),
];

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

fn request() -> Packet {
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

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running(Child);

impl Running {
    fn success(mut self) {
        assert!(self.0.wait().unwrap().success());
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn spawn(role: &str, uid: u32, root: &Path) -> Running {
    Running(
        Command::new("setpriv")
            .args([
                format!("--reuid={uid}"),
                format!("--regid={uid}"),
                "--clear-groups".into(),
                "--bounding-set=-all".into(),
                "--inh-caps=-all".into(),
                "--ambient-caps=-all".into(),
                "--no-new-privs".into(),
                "--".into(),
            ])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "publisher_local_vm_role",
                "--ignored",
                "--nocapture",
            ])
            .env("TERRANE_PUBLISHER_VM_ROLE", role)
            .env("TERRANE_PUBLISHER_VM_ROOT", root)
            .spawn()
            .unwrap(),
    )
}

#[test]
#[ignore = "requires the dedicated multi-UID Linux VM"]
fn publisher_local_multuid_vm() {
    assert_eq!(std::env::var("TERRANE_PUBLISHER_VM").as_deref(), Ok("1"));
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let scratch = Scratch(PathBuf::from(format!(
        "/var/lib/terrane-publisher-local-tests-{}",
        std::process::id()
    )));
    fs::create_dir(&scratch.0).unwrap();
    fs::set_permissions(&scratch.0, fs::Permissions::from_mode(0o755)).unwrap();
    chown(
        &scratch.0,
        Some(Uid::from_raw(PUBLISH)),
        Some(Gid::from_raw(PUBLISH)),
    )
    .unwrap();
    let sealed = scratch.0.join("sealed");
    fs::create_dir(&sealed).unwrap();
    chown(
        &sealed,
        Some(Uid::from_raw(PUBLISH)),
        Some(Gid::from_raw(PUBLISH)),
    )
    .unwrap();
    fs::set_permissions(&sealed, fs::Permissions::from_mode(0o700)).unwrap();

    let publisher = spawn("publisher", PUBLISH, &scratch.0);
    for attempt in 0..1000 {
        if scratch.0.join("ready").exists() {
            break;
        }
        assert!(attempt < 999, "publisher did not bind");
        thread::sleep(Duration::from_millis(10));
    }
    spawn("outsider", OUTSIDER, &scratch.0).success();
    for (role, uid) in OTHER_ROLES {
        spawn(role, uid, &scratch.0).success();
    }
    spawn("serve", SERVE, &scratch.0).success();
    publisher.success();
    let sealed_metadata = sealed.metadata().unwrap();
    assert_eq!(sealed_metadata.uid(), PUBLISH);
    assert_eq!(sealed_metadata.gid(), PUBLISH);
    assert_eq!(sealed_metadata.mode() & 0o7777, 0o700);
    assert_eq!(fs::read_dir(&sealed).unwrap().count(), 1);
    assert_eq!(
        fs::read(sealed.join("publisher-owned")).unwrap(),
        b"publisher"
    );
}

fn check_process_identity(role: &str) {
    let uid = match role {
        "publisher" => PUBLISH,
        "serve" => SERVE,
        "outsider" => OUTSIDER,
        other => OTHER_ROLES
            .iter()
            .find_map(|(name, uid)| (*name == other).then_some(*uid))
            .expect("registered role"),
    };
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for field in ["Uid", "Gid"] {
        let line = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))
            .unwrap();
        assert_eq!(
            line.split_whitespace().collect::<Vec<_>>(),
            vec![uid.to_string(); 4]
        );
    }
    for field in ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))
            .unwrap();
        assert_eq!(value.trim(), "0000000000000000");
    }
    assert_eq!(
        status
            .lines()
            .find_map(|line| line.strip_prefix("Groups:"))
            .unwrap()
            .trim(),
        ""
    );
    assert_eq!(
        status
            .lines()
            .find_map(|line| line.strip_prefix("NoNewPrivs:"))
            .unwrap()
            .trim(),
        "1"
    );
    // Libtest may have printed its unfinished test label without a newline.
    println!(
        "\nPUBLISHER_ROLE_IDENTITY role={role} uid={uid} gid={uid} groups=none caps=zero nnp=1"
    );
}

fn assert_permission_denied<T>(result: std::io::Result<T>) {
    match result {
        Ok(_) => panic!("non-publisher mutated the sealed namespace"),
        Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
    }
}

fn reject_sealed_mutations(root: &Path, role: &str) {
    let sealed = root.join("sealed");
    let original = sealed.join("publisher-owned");
    let attempted = sealed.join(role);

    assert_permission_denied(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&attempted),
    );
    assert_permission_denied(OpenOptions::new().write(true).open(&original));
    assert_permission_denied(fs::create_dir(&attempted));
    assert_permission_denied(fs::rename(&original, &attempted));
    assert_permission_denied(fs::remove_file(&original));
    assert_permission_denied(fs::set_permissions(
        &sealed,
        fs::Permissions::from_mode(0o777),
    ));
    assert_permission_denied(fs::set_permissions(
        &original,
        fs::Permissions::from_mode(0o666),
    ));
    println!("PASS sealed namespace mutations refused role={role}");
}

#[test]
#[ignore = "subprocess fixture, invoked only by publisher_local_multuid_vm"]
fn publisher_local_vm_role() {
    assert_eq!(std::env::var("TERRANE_PUBLISHER_VM").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("TERRANE_PUBLISHER_VM_ROOT").unwrap());
    let socket = root.join("publisher.sock");
    let role = std::env::var("TERRANE_PUBLISHER_VM_ROLE").unwrap();
    check_process_identity(&role);
    if role != "publisher" {
        reject_sealed_mutations(&root, &role);
    }
    match role.as_str() {
        "publisher" => {
            assert_eq!(rustix::process::geteuid().as_raw(), PUBLISH);
            let listener = Listener::bind(&socket, identities()).unwrap();
            // World-connectable fixture permission proves authentication is
            // kernel-credential based even when pathname access is possible.
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
            fs::write(root.join("sealed/publisher-owned"), b"publisher").unwrap();
            drop(File::create_new(root.join("ready")).unwrap());
            assert!(matches!(listener.accept(), Err(Error::Denied)));
            let connection = listener.accept().unwrap();
            let received = connection.receive(&policy()).unwrap();
            assert_eq!(received.packet, request());
            // This is a transport correlation fixture, not native completion.
            let response = Packet {
                response: true,
                result: 5,
                wait_budget_ms: 0,
                ..received.packet
            };
            connection.send(&response, &[], &policy()).unwrap();
        }
        "outsider" => {
            assert!(matches!(
                Connection::connect(&socket, identities()),
                Err(Error::Denied)
            ));
            let raw = net::socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )
            .unwrap();
            net::connect(&raw, &net::SocketAddrUnix::new(&socket).unwrap()).unwrap();
        }
        "serve" => {
            assert!(fs::read(root.join("sealed/publisher-owned")).is_err());
            let connection = Connection::connect(&socket, identities()).unwrap();
            connection.send(&request(), &[], &policy()).unwrap();
            assert_eq!(connection.receive(&policy()).unwrap().packet.result, 5);
        }
        "realize" | "gc" | "worker" | "sandbox" => {}
        role => panic!("unexpected VM role: {role}"),
    }
}
