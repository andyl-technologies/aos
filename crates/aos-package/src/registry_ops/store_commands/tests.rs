//! Tests for realisation graph maintenance and store signing-key selection.

use super::resolve_cache_pointer_signing_key;
use crate::config::ApmConfig;
use crate::registry_ops::test_support::{
    test_config_with_signing_key, test_registry_config, write_seeded_signing_key, write_test_roster,
};
use crate::types::{ApmSettings, ProfileScope};
use tempfile::TempDir;

#[test]
fn cache_pointer_commit_selects_the_only_configured_active_key() {
    let tmp = TempDir::new().unwrap();
    let key = write_seeded_signing_key(tmp.path(), "maintenance", [31_u8; 32], "maintainer");
    write_test_roster(tmp.path(), "maintainer", &key.trusted_key, &[]).unwrap();
    let config = test_config_with_signing_key("maintenance", "maintainer", &key.private_key);

    let resolved =
        resolve_cache_pointer_signing_key(&config, tmp.path(), "maintenance", None, None)
            .unwrap()
            .unwrap();

    assert_eq!(resolved.path(), key.private_key.to_str().unwrap());
}

#[test]
fn cache_pointer_commit_fails_closed_without_active_private_material() {
    let tmp = TempDir::new().unwrap();
    let key = write_seeded_signing_key(tmp.path(), "maintenance", [32_u8; 32], "maintainer");
    write_test_roster(tmp.path(), "maintainer", &key.trusted_key, &[]).unwrap();
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: vec![(test_registry_config("maintenance", None), None)],
        scope: ProfileScope::User,
    };

    let error = resolve_cache_pointer_signing_key(&config, tmp.path(), "maintenance", None, None)
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("none has local private key material")
    );
}
