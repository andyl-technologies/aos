//! Checks the closed administrative configuration vocabulary.

#![cfg(target_os = "linux")]

use aos_terrane::host::HostConfig;

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
    use terrane_fs::host_quota::{DomainProvisioningGuard, NativeProject, ROOT_LABELS};

    assert_eq!(std::env::var("TERRANE_HOST_QUOTA_VM").as_deref(), Ok("1"));
    let mount =
        PathBuf::from(std::env::var_os("TERRANE_HOST_QUOTA_ADMIN_ROOT").expect("guest mount"));
    let host = mount.join("host-ledger");
    let layout = mount.join("ledger-owner");
    fs::create_dir(&host).expect("host administrative directory");
    fs::create_dir(&layout).expect("domain layout");
    fs::set_permissions(&host, fs::Permissions::from_mode(0o700)).expect("host custody");
    for label in ROOT_LABELS {
        if label != "layout-root" {
            fs::create_dir(layout.join(label)).expect("allocation class");
        }
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
    assert!(aos_terrane::host::provision(&config, &ledger).is_err());
    assert!(!ledger.exists());
    drop(active_factory);

    aos_terrane::host::provision(&config, &ledger).expect("explicit quiescent host provisioning");
    assert_eq!(
        NativeProject::inspect(&root)
            .expect("native project")
            .project_id,
        41002
    );
    let original_ledger = fs::read(&ledger).expect("durable ownership ledger");
    fs::write(&config, configuration("tenant:other")).expect("attempted domain reassignment");
    assert!(aos_terrane::host::provision(&config, &ledger).is_err());
    assert!(aos_terrane::host::serve(&config, &ledger).is_err());
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
    let backup = host.join("ledger.backup");
    fs::rename(&ledger, &backup).expect("simulate missing ledger");
    assert!(aos_terrane::host::provision(&config, &ledger).is_err());
    assert!(!ledger.exists());
    fs::rename(&backup, &ledger).expect("restore retained ledger");
    aos_terrane::host::provision(&config, &ledger).expect("idempotent original assignment");

    drop(root);
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
