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
