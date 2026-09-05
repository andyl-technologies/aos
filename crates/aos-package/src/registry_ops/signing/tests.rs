//! Tests for producer signing-key resolution and ephemeral command-backed key material.

use super::{
    executable_on_path, materialize_signing_key_command_with_path, resolve_producer_signing_key,
    resolve_signing_key_source,
};
use crate::config::ApmConfig;
use crate::registry_ops::git::git;
use crate::registry_ops::tags::sign_tag;
use crate::registry_ops::test_support::{
    test_config_with_signing_key, test_registry_config, write_test_roster, write_test_signing_key,
};
use crate::security::verify_tag_signature;
use crate::types::{ApmSettings, ProfileScope, SigningKeySource, SigningKeySpec};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[test]
fn producer_signing_key_direct_path_bypasses_key_id_lookup() {
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: Vec::new(),
        scope: ProfileScope::User,
    };
    let resolved = resolve_producer_signing_key(
        &config,
        Path::new("/missing"),
        "aos-core",
        Some("/tmp/key"),
        None,
    )
    .unwrap();

    assert_eq!(resolved.path(), "/tmp/key");
}

#[test]
fn producer_signing_key_rejects_ambiguous_key_sources() {
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: Vec::new(),
        scope: ProfileScope::User,
    };
    let err = resolve_producer_signing_key(
        &config,
        Path::new("/missing"),
        "aos-core",
        Some("/tmp/key"),
        Some("initial"),
    )
    .unwrap_err();

    assert!(format!("{err:#}").contains("use only one of --key or --key-id"));
}

#[test]
fn producer_signing_key_id_resolves_configured_private_key() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let signing = write_test_signing_key(tmp.path(), "aos-core");
    write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
    let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);

    let resolved =
        resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial")).unwrap();

    assert_eq!(PathBuf::from(resolved.path()), signing.private_key);
}

#[test]
fn producer_signing_key_id_rejects_missing_local_mapping() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let signing = write_test_signing_key(tmp.path(), "aos-core");
    write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: vec![(test_registry_config("aos-core", None), None)],
        scope: ProfileScope::User,
    };

    let err = resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
        .unwrap_err();

    assert!(format!("{err:#}").contains("no local private key configured"));
}

#[test]
fn producer_signing_key_id_rejects_revoked_key() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir(&repo).unwrap();
    let signing = write_test_signing_key(tmp.path(), "aos-core");
    write_test_roster(&repo, "initial", &signing.trusted_key, &["initial"]).unwrap();
    let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);

    let err = resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial"))
        .unwrap_err();

    assert!(format!("{err:#}").contains("revoked"));
}

#[test]
fn producer_signing_key_id_signs_verifiable_release_tag() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=main",
            repo.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();

    let signing = write_test_signing_key(tmp.path(), "aos-core");
    write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();

    let config = test_config_with_signing_key("aos-core", "initial", &signing.private_key);
    let resolved =
        resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial")).unwrap();
    sign_tag(
        &repo,
        "1.0.0",
        "HEAD",
        Some("AOS registry release"),
        resolved.path(),
        false,
    )
    .unwrap();

    assert!(
        verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&signing.trusted_key)).unwrap()
    );
}

#[test]
fn producer_signing_key_command_source_signs_verifiable_release_tag() {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    git(
        tmp.path(),
        &[
            "init",
            "--object-format=sha256",
            "--initial-branch=main",
            repo.to_str().unwrap(),
        ],
    )
    .unwrap();
    git(&repo, &["config", "user.name", "AOS Registry"]).unwrap();
    git(&repo, &["config", "user.email", "registry@example.com"]).unwrap();
    git(&repo, &["config", "commit.gpgsign", "false"]).unwrap();
    fs::write(
        repo.join("registry.toml"),
        "[registry]\nname = \"aos-core\"\n",
    )
    .unwrap();

    let signing = write_test_signing_key(tmp.path(), "aos-core");
    write_test_roster(&repo, "initial", &signing.trusted_key, &[]).unwrap();
    git(&repo, &["add", "."]).unwrap();
    git(&repo, &["commit", "-m", "init"]).unwrap();

    // A command source: `cat` the key file just-in-time. This exercises
    // the materialize-to-tempfile path that `ssh-keygen`'s double-open
    // requires (a pipe would fail here).
    let mut registry_config = test_registry_config("aos-core", None);
    registry_config.signing_keys.insert(
        "initial".to_string(),
        SigningKeySource::Spec(SigningKeySpec {
            path: None,
            command: Some(format!("cat {}", signing.private_key.display())),
        }),
    );
    let config = ApmConfig {
        settings: ApmSettings::default(),
        registries: vec![(registry_config, None)],
        scope: ProfileScope::User,
    };

    let resolved =
        resolve_producer_signing_key(&config, &repo, "aos-core", None, Some("initial")).unwrap();
    // The key was materialized into a fresh temp file, not the original.
    assert_ne!(resolved.path(), signing.private_key.to_str().unwrap());
    let materialized = PathBuf::from(resolved.path());
    assert!(materialized.exists());

    sign_tag(
        &repo,
        "1.0.0",
        "HEAD",
        Some("AOS registry release"),
        resolved.path(),
        false,
    )
    .unwrap();
    assert!(
        verify_tag_signature(&repo, "1.0.0", std::slice::from_ref(&signing.trusted_key)).unwrap()
    );

    // Dropping the resolved key removes the materialized temp file.
    drop(resolved);
    assert!(!materialized.exists());
}

#[test]
fn producer_signing_key_command_failure_is_reported() {
    let source = SigningKeySource::Spec(SigningKeySpec {
        path: None,
        command: Some("exit 3".to_string()),
    });
    let err = resolve_signing_key_source("initial", &source).unwrap_err();
    assert!(format!("{err:#}").contains("signing key command"));
}

#[test]
fn signing_key_command_runs_with_search_path_override() {
    // Passing the current PATH through the override exercises the same
    // code path the wrappers trigger via AOS_HOST_PATH.
    let resolved = materialize_signing_key_command_with_path(
        "printf 'key material'",
        std::env::var_os("PATH"),
    )
    .unwrap();
    assert_eq!(fs::read_to_string(resolved.path()).unwrap(), "key material");
}

#[test]
fn signing_key_command_finds_host_path_helpers() {
    let tmp = TempDir::new().unwrap();
    let helper = tmp.path().join("emit-signing-key");
    let runtime_path = std::env::var_os("PATH").unwrap();
    let bash = executable_on_path("bash", &runtime_path).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(bash, &helper).unwrap();
    }
    #[cfg(not(unix))]
    {
        fs::copy(bash, &helper).unwrap();
    }

    let resolved = materialize_signing_key_command_with_path(
        "emit-signing-key -c \"printf 'host key material'\"",
        Some(tmp.path().as_os_str().to_os_string()),
    )
    .unwrap();
    assert_eq!(
        fs::read_to_string(resolved.path()).unwrap(),
        "host key material"
    );
}

#[test]
fn signing_key_command_shell_resolution_survives_path_override() {
    // The shell itself is resolved from the runtime PATH before the
    // user command sees the override, so shell builtins still work.
    let tmp = TempDir::new().unwrap();
    let resolved = materialize_signing_key_command_with_path(
        "printf 'key material'",
        Some(tmp.path().as_os_str().to_os_string()),
    )
    .unwrap();
    assert_eq!(fs::read_to_string(resolved.path()).unwrap(), "key material");
}

#[test]
fn signing_key_command_search_path_override_replaces_command_path() {
    let tmp = TempDir::new().unwrap();
    let err = materialize_signing_key_command_with_path(
        "cat /definitely/missing",
        Some(tmp.path().as_os_str().to_os_string()),
    )
    .unwrap_err();
    assert!(format!("{err:#}").contains("signing key command"));
}

#[test]
fn signing_key_source_rejects_both_path_and_command() {
    let source = SigningKeySource::Spec(SigningKeySpec {
        path: Some("/tmp/key".to_string()),
        command: Some("cat /tmp/key".to_string()),
    });
    let err = resolve_signing_key_source("initial", &source).unwrap_err();
    assert!(format!("{err:#}").contains("both 'path' and 'command'"));
}
