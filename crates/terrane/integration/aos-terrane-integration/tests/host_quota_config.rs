//! Checks the closed administrative configuration vocabulary.

#![cfg(target_os = "linux")]
#![allow(
    clippy::expect_used,
    reason = "Test assertions panic on fixture failures."
)]

use aos_terrane_integration::host::HostConfig;

#[test]
fn configuration_rejects_mutation_command_fields() {
    let config = r#"
socket = "/run/terrane-host/quota.sock"
epoch = "00000000000000000000000000000001"
tier_charge_budget_bytes = 4096
owners = []
command = "setquota"
"#;
    assert!(toml::from_str::<HostConfig>(config).is_err());
}

#[test]
#[ignore = "requires the explicit host-quota-proof ext4 VM"]
fn host_quota_admin_ledger_preserves_domain_and_project_vm() {
    use std::fs::{self, File};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use terrane_linux::host_quota::{DomainProvisioningGuard, NativeProject, ROOT_LABELS};

    assert_eq!(std::env::var("TERRANE_HOST_QUOTA_VM").as_deref(), Ok("1"));
    let status = fs::read_to_string("/proc/self/status").expect("actual capability state");
    for field in ["CapEff", "CapPrm", "CapBnd"] {
        assert!(
            status
                .lines()
                .any(|line| line == format!("{field}:\t000000000020001d")),
            "bounded provisioning capability set: {field}"
        );
    }
    let groups = status
        .lines()
        .find(|line| line.starts_with("Groups:"))
        .expect("supplementary groups");
    assert!(
        !groups
            .split_whitespace()
            .skip(1)
            .any(|group| group == "844" || group == "845")
    );
    let mount =
        PathBuf::from(std::env::var_os("TERRANE_HOST_QUOTA_ADMIN_ROOT").expect("guest mount"));
    let registry = std::path::Path::new("/var/lib/terrane-host/project-claims");
    fs::create_dir_all(registry).expect("fixed host registry");
    fs::set_permissions(
        registry.parent().expect("registry parent"),
        fs::Permissions::from_mode(0o700),
    )
    .expect("administrative parent custody");
    fs::set_permissions(registry, fs::Permissions::from_mode(0o700)).expect("registry custody");
    let host = mount.join("host-ledger");
    let layout = mount.join("ledger-owner");
    fs::create_dir(&host).expect("host administrative directory");
    fs::create_dir(&layout).expect("domain layout");
    fs::set_permissions(&host, fs::Permissions::from_mode(0o700)).expect("host custody");
    for label in ROOT_LABELS {
        if label != "layout-root" {
            fs::create_dir(layout.join(label)).expect("allocation class");
            let (uid, gid, mode) = match label {
                "state" => (0, 0, 0o755),
                "sealed" | "staging" | "pending-delete" => (841, 841, 0o700),
                _ => (840, 845, 0o2770),
            };
            std::os::unix::fs::chown(layout.join(label), Some(uid), Some(gid))
                .expect("original role ownership");
            fs::set_permissions(layout.join(label), fs::Permissions::from_mode(mode))
                .expect("original role mode");
        }
    }
    for (label, uid, gid, mode) in [
        ("cache", 840, 844, 0o2770),
        ("publication", 841, 841, 0o700),
    ] {
        let path = layout.join("state").join(label);
        fs::create_dir(&path).expect("state scaffold");
        std::os::unix::fs::chown(&path, Some(uid), Some(gid)).expect("state scaffold ownership");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("state scaffold mode");
    }
    let config = host.join("host.toml");
    let ledger = host.join("ledger.toml");
    let configuration = |domain: &str| {
        let mut text = format!(
            "socket = {:?}\nepoch = \"00000000000000000000000000000001\"\ntier_charge_budget_bytes = 4194304\n[[owners]]\nowner_id = \"ledger-owner\"\ndomain = {domain:?}\nproject_id = 41002\nhard_limit_bytes = 2097152\nallowed_client_uids = [840]\n",
            host.join("quota.sock").to_str().expect("UTF-8 fixture")
        );
        for label in ROOT_LABELS {
            let path = if label == "layout-root" {
                layout.clone()
            } else {
                layout.join(label)
            };
            text.push_str(&format!(
                "[[owners.roots]]\nrole_directory = {label:?}\npath = {:?}\n",
                path.to_str().expect("UTF-8 root")
            ));
        }
        text
    };
    fs::write(&config, configuration("public")).expect("protected configuration");
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).expect("configuration custody");
    let root = File::open(&layout).expect("retained layout");
    let active_factory = DomainProvisioningGuard::shared(&root).expect("native factory guard");
    assert!(aos_terrane_integration::host::provision(&config, &ledger).is_err());
    assert!(!ledger.exists());
    drop(active_factory);
    fs::write(layout.join("state/unprovisioned-body"), b"body").expect("unexpected body fixture");
    assert!(aos_terrane_integration::host::provision(&config, &ledger).is_err());
    assert!(!ledger.exists());
    fs::remove_file(layout.join("state/unprovisioned-body")).expect("unexpected body cleanup");

    aos_terrane_integration::host::provision(&config, &ledger)
        .expect("explicit quiescent host provisioning");
    assert_eq!(
        NativeProject::inspect(&root)
            .expect("native project")
            .project_id,
        41002
    );
    for (label, uid, gid, mode) in [
        ("cache", 840, 844, 0o2770),
        ("publication", 841, 841, 0o700),
    ] {
        use std::os::unix::fs::MetadataExt;
        let file =
            File::open(layout.join("state").join(label)).expect("retained restored scaffold");
        let identity = NativeProject::inspect(&file).expect("actual scaffold project");
        assert_eq!(identity.project_id, 41002);
        assert!(identity.inherit);
        let metadata = file.metadata().expect("restored scaffold metadata");
        assert_eq!(
            (metadata.uid(), metadata.gid(), metadata.mode() & 0o7777),
            (uid, gid, mode)
        );
    }
    let original_ledger = fs::read(&ledger).expect("durable ownership ledger");
    fs::write(&config, configuration("tenant:other")).expect("attempted domain reassignment");
    assert!(aos_terrane_integration::host::provision(&config, &ledger).is_err());
    assert!(aos_terrane_integration::host::serve(&config, &ledger).is_err());
    assert_eq!(
        fs::read(&ledger).expect("unchanged ledger"),
        original_ledger
    );
    assert_eq!(
        NativeProject::inspect(&root)
            .expect("unchanged project")
            .project_id,
        41002
    );

    fs::write(&config, configuration("public")).expect("restore original domain");
    let interrupted = String::from_utf8(original_ledger.clone())
        .expect("ledger UTF-8")
        .replacen("phase = \"ready\"", "phase = \"provisioning\"", 1);
    assert!(interrupted.contains("phase = \"provisioning\""));
    fs::write(&ledger, interrupted).expect("simulate durable incomplete phase");
    let scaffold = File::open(layout.join("state/cache")).expect("retained interrupted scaffold");
    terrane_linux::host_quota::set_directory_custody(&scaffold, 0, 0, 0o700)
        .expect("simulate root custody progress");
    assert!(aos_terrane_integration::host::serve(&config, &ledger).is_err());
    aos_terrane_integration::host::provision(&config, &ledger)
        .expect("explicit interrupted provisioning recovery");
    assert_eq!(
        fs::read(&ledger).expect("restored ready ledger"),
        original_ledger
    );
    drop(scaffold);
    let backup = host.join("ledger.backup");
    fs::rename(&ledger, &backup).expect("simulate missing ledger");
    assert!(aos_terrane_integration::host::provision(&config, &ledger).is_err());
    assert!(!ledger.exists());
    fs::rename(&backup, &ledger).expect("restore retained ledger");
    aos_terrane_integration::host::provision(&config, &ledger)
        .expect("idempotent original assignment");

    drop(root);
    fs::remove_dir(layout.join("state/cache")).expect("cache scaffold cleanup");
    fs::remove_dir(layout.join("state/publication")).expect("publication scaffold cleanup");
    for label in ROOT_LABELS {
        if label != "layout-root" {
            fs::remove_dir(layout.join(label)).expect("allocation root cleanup");
        }
    }
    fs::remove_dir(layout).expect("layout cleanup");
    fs::remove_file(config).expect("configuration cleanup");
    fs::remove_file(ledger).expect("ledger cleanup");
    fs::remove_dir(host).expect("host directory cleanup");
}
