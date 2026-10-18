//! Exercises actual project enforcement and capability-free helper queries in a VM.
//!
//! These ignored cases require the explicit host-quota-proof guest marker and
//! an actual ext4 project-quota mount; ordinary package checks never qualify them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

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
        "userns" => {
            assert!(terrane_fs::host_quota::require_host_root_namespace_boundary().is_err());
            assert!(HostQuotaClient::connect(&root.join("quota.sock"), 0, [1; 16]).is_err());
        }
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
        let path = if label == "layout-root" {
            root.clone()
        } else {
            root.join(label)
        };
        if label != "layout-root" {
            fs::create_dir(&path).expect("create allocation root");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("role-readable root");
        if label != "layout-root" {
            std::os::unix::fs::chown(&path, Some(840), Some(840)).expect("role allocation custody");
        }
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
    assert!(terrane_fs::host_quota::require_unused_project(&roots[0].directory, 41001).is_err());
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
    let registry = root.join("fixture-claims");
    fs::create_dir(&registry).expect("fixture protected registry");
    fs::set_permissions(&registry, fs::Permissions::from_mode(0o700)).expect("registry custody");
    let uuid = filesystem_uuid(&roots[0].directory).expect("filesystem UUID");
    let record =
        registry.join(terrane_fs::host_quota::project_claim_name(&uuid, 41001).expect("claim key"));
    fs::write(&record, b"fixture host claim").expect("host claim");
    fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).expect("claim custody");
    let anchor = registry.join("fixture.identity");
    fs::write(&anchor, b"fixture registry identity").expect("registry anchor");
    fs::set_permissions(&anchor, fs::Permissions::from_mode(0o600)).expect("anchor custody");
    let claim = terrane_fs::host_quota::RetainedProjectClaim::open(
        &registry,
        &anchor,
        b"fixture registry identity",
        uuid,
        41001,
        b"fixture host claim",
    )
    .expect("retained actual claim");
    let owner = ConfiguredOwner {
        owner_id: "public-owner".into(),
        domain: "public".into(),
        filesystem_uuid: filesystem_uuid(&roots[0].directory).expect("filesystem UUID"),
        project_id: 41001,
        hard_limit_bytes: 2 * 1024 * 1024,
        allowed_client_uids: BTreeSet::from([840]),
        roots,
        scaffolding: Vec::new(),
        claim: Some(claim),
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
    fs::remove_file(record).expect("remove fixture claim");
    fs::remove_file(anchor).expect("remove fixture anchor");
    fs::remove_dir(registry).expect("remove fixture registry");
    for label in ROOT_LABELS {
        if label != "layout-root" {
            fs::remove_dir(root.join(label)).expect("remove allocation root");
        }
    }
}
