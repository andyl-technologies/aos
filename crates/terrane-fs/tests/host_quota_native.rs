//! Exercises actual project enforcement and capability-free helper queries in a VM.
//!
//! These ignored cases require the explicit host-quota-proof guest marker and
//! an actual ext4 project-quota mount; ordinary package checks never qualify them.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use terrane_fs::host_quota::{
    ConfiguredOwner, ConfiguredRoot, HostQuotaBroker, HostQuotaClient, NativeProject, NativeQuota,
    ROOT_LABELS, filesystem_uuid, provision_project, synchronized_allocated_bytes,
};

fn marker() {
    assert_eq!(std::env::var("TERRANE_HOST_QUOTA_VM").as_deref(), Ok("1"));
}

#[test]
#[ignore = "requires the explicit host-quota-proof ext4 VM"]
fn host_quota_vm_role() {
    marker();
    let root = PathBuf::from(std::env::var_os("TERRANE_HOST_QUOTA_ROOT").expect("guest root"));
    match std::env::var("TERRANE_HOST_QUOTA_ROLE")
        .expect("child role")
        .as_str()
    {
        "direct" => {
            let error =
                NativeQuota::query(&File::open(root.join("chunks")).expect("open root"), 41001)
                    .expect_err("unprivileged project query must fail");
            assert_eq!(error.raw_os_error(), Some(1));
        }
        "helper" => {
            let mut client = HostQuotaClient::connect(&root.join("quota.sock"), 0, [1; 16])
                .expect("root helper");
            let result = client
                .query("public-owner", "public")
                .expect("live helper observation");
            let observation = result.observation();
            assert!(observation.accounting && observation.enforcement);
            assert_eq!(observation.project_id, 41001);
            assert_eq!(observation.hard_limit_bytes, 2 * 1024 * 1024);
            assert_eq!(observation.roots.len(), ROOT_LABELS.len());
            let mut allocation =
                File::create(root.join("chunks/quota-exhaustion")).expect("role allocation");
            use std::io::Write;
            let error = allocation
                .write_all(&vec![0u8; 3 * 1024 * 1024])
                .expect_err("finite native project quota must refuse excess allocation");
            assert_eq!(error.raw_os_error(), Some(122));
            drop(allocation);
            fs::remove_file(root.join("chunks/quota-exhaustion"))
                .expect("cleanup denied allocation");
            assert!(client.query("public-owner", "private:other").is_err());
        }
        _ => panic!("unknown fixture role"),
    }
}

#[test]
#[ignore = "requires the explicit host-quota-proof ext4 VM"]
fn host_quota_native_privilege_and_helper_vm() {
    marker();
    let root = PathBuf::from(std::env::var_os("TERRANE_HOST_QUOTA_ROOT").expect("guest root"));
    fs::create_dir_all(&root).expect("create fixture");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("protect fixture");
    let mut roots = Vec::new();
    for label in ROOT_LABELS {
        let path = root.join(label);
        fs::create_dir(&path).expect("create allocation root");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("role-readable root");
        std::os::unix::fs::chown(&path, Some(840), Some(840)).expect("role allocation custody");
        let directory = File::open(&path).expect("open allocation root");
        provision_project(&directory, 41001, 2 * 1024 * 1024).expect("host quota provisioning");
        let identity = NativeProject::inspect(&directory).expect("actual project");
        assert_eq!(identity.project_id, 41001);
        assert!(identity.inherit);
        roots.push(ConfiguredRoot {
            role_directory: label.into(),
            directory,
            device: identity.device,
            inode: identity.inode,
        });
    }
    let quota = NativeQuota::query(&roots[0].directory, 41001).expect("privileged actual query");
    assert_eq!(quota.hard_limit_bytes, 2 * 1024 * 1024);
    let file = File::create(root.join("chunks/body")).expect("create body");
    file.set_len(1024 * 1024).expect("sparse logical length");
    assert!(synchronized_allocated_bytes(&file).expect("synchronized allocation") < 1024 * 1024);
    drop(file);
    fs::remove_file(root.join("chunks/body")).expect("cleanup body");

    let child = |role: &str| {
        let result = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", "host_quota_vm_role", "--ignored", "--nocapture"])
            .env("TERRANE_HOST_QUOTA_ROLE", role)
            .uid(840)
            .gid(840)
            .output()
            .expect("spawn role");
        assert!(
            result.status.success(),
            "role {role}: {}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed; 0 failed; 0 ignored"));
    };
    child("direct");
    let socket = root.join("quota.sock");
    let owner = ConfiguredOwner {
        owner_id: "public-owner".into(),
        domain: "public".into(),
        filesystem_uuid: filesystem_uuid(&roots[0].directory).expect("filesystem UUID"),
        project_id: 41001,
        hard_limit_bytes: 2 * 1024 * 1024,
        allowed_client_uids: BTreeSet::from([840]),
        roots,
    };
    let broker =
        HostQuotaBroker::bind(&socket, [1; 16], 4 * 1024 * 1024, vec![owner]).expect("bind broker");
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).expect("role socket access");
    let server = std::thread::spawn(move || {
        let _ = broker.serve_connection();
    });
    child("helper");
    server.join().expect("server completion");
    fs::remove_file(socket).expect("remove socket");
    for label in ROOT_LABELS {
        fs::remove_dir(root.join(label)).expect("remove allocation root");
    }
}
