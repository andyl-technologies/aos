//! Checks whole collector compositions without executor, credential or filesystem effects.

#![allow(
    clippy::unwrap_used,
    reason = "Pure preflight assertions intentionally panic on unexpected syntax refusal."
)]

use super::*;

const INPUT: &str = r#"
role = "gc"
store = "bucket(file:///var/lib/terrane-store)"
[tokens]
issuer_public_keys = ["file:/etc/terrane/operator.pub"]
[local_repository]
authority_directory = "/var/lib/terrane-authority"
issuer = "operator"
key_id = "current"
owner_uid = 840
store_name = "local"
domain = "private:owner"
default_private_domain = "private:owner"
current_reference = "refs/heads/_/main"
acl = []
[local_repository.timing]
maximum_ms = 30001
grace_ms = 60001
margin_ms = 10000
[gc]
lease_seconds = 300
poll_ms = 1000
cycle_interval_ms = 60000
mark_batch = 32
maintenance_batch = 8
deletion_seconds = 61
"#;

#[test]
fn pure_preflight_accepts_unopened_local_inputs() {
    let config = Config::parse(INPUT).unwrap();
    let plan = preflight(&config, Role::Gc).unwrap();

    assert_eq!(plan.windows.commit(), 31);
    assert_eq!(plan.windows.grace(), 61);
    assert_eq!(plan.windows.deletion(), 61);
    assert_eq!(plan.settings.lease_seconds, 300);
}

#[test]
fn pure_preflight_refuses_remote_composite_and_conflicting_roles() {
    for store in [
        "bucket(s3://example-bucket)",
        "guard(policy=warehouse)(bucket(file:///var/lib/terrane-store))",
    ] {
        let input = INPUT.replace("bucket(file:///var/lib/terrane-store)", store);
        let config = Config::parse(&input).unwrap();

        assert!(matches!(
            preflight(&config, Role::Gc),
            Err(Error::Refused(_))
        ));
    }

    let input = INPUT.replace("role = \"gc\"", "role = \"serve\"");
    let config = Config::parse(&input).unwrap();
    assert!(matches!(preflight(&config, Role::Gc), Err(Error::Role(_))));
    assert!(matches!(
        preflight(&config, Role::Serve),
        Err(Error::Refused(_))
    ));
}

#[test]
fn pure_preflight_refuses_instance_credentials_and_missing_public_keys() {
    let input = INPUT.replace("[tokens]", "[tokens]\nhost_token = 'file:/must-not-open'");
    let config = Config::parse(&input).unwrap();
    assert!(matches!(
        preflight(&config, Role::Gc),
        Err(Error::Refused(_))
    ));

    let input = INPUT.replace("[\"file:/etc/terrane/operator.pub\"]", "[]");
    let config = Config::parse(&input).unwrap();
    assert!(matches!(
        preflight(&config, Role::Gc),
        Err(Error::Refused(_))
    ));
}

#[test]
fn pure_preflight_refuses_overlapping_authority_and_missing_settings() {
    let input = INPUT.replace(
        "/var/lib/terrane-authority",
        "/var/lib/terrane-store/authority",
    );
    let config = Config::parse(&input).unwrap();
    assert!(matches!(
        preflight(&config, Role::Gc),
        Err(Error::Refused(_))
    ));

    let config = Config::parse(INPUT.split("[gc]").next().unwrap()).unwrap();
    assert!(matches!(
        preflight(&config, Role::Gc),
        Err(Error::Refused(_))
    ));
}
