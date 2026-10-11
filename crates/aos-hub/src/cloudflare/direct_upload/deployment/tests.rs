//! Protected secret custody, persistent credential pairing and preservation tests.

use super::*;
use crate::cloudflare::direct_upload::tests::config;

fn mirror_config() -> HybridDeployConfig {
    let mut cfg = config();
    cfg.mirror_trust = Some(crate::cloudflare::HybridMirrorTrustConfig {
        public_key: hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[73; 32])
                .verifying_key()
                .as_bytes(),
        ),
        namespace_id: "mirror-review-registry".into(),
    });
    cfg
}

#[cfg(unix)]
#[test]
fn mirror_reuses_only_the_native_matched_guard_role_after_separation_checks() {
    let cfg = mirror_config();
    let directory = private_directory();
    let producer = "p".repeat(64);
    let guard = "g".repeat(64);
    let mut files = HybridDeploySecretFiles {
        storage_work_key_file: Some(secret(directory.path(), "producer", &producer)),
        direct_upload_guard_key_file: Some(secret(directory.path(), "guard", &guard)),
        ..HybridDeploySecretFiles::default()
    };

    let protected = ProtectedSecrets::read(&files, &cfg).unwrap();
    let selected = |name| {
        protected
            .entries
            .iter()
            .find(|(key, _)| *key == name)
            .unwrap()
            .1
            .as_str()
    };
    assert_eq!(selected("HUB_MIRROR_GUARD_KEY"), guard);
    assert_eq!(selected("HUB_DIRECT_UPLOAD_GUARD_KEY"), guard);
    assert_ne!(selected("HUB_STORAGE_WORK_KEY"), guard);

    files.direct_upload_guard_key_file = files.storage_work_key_file.clone();
    assert!(ProtectedSecrets::read(&files, &cfg).is_err());
}

#[test]
fn mirror_update_requires_the_existing_guard_binding_without_reading_its_value() {
    let cfg = mirror_config();
    let protected = ProtectedSecrets::read(&HybridDeploySecretFiles::default(), &cfg).unwrap();
    let mut existing: Vec<String> = [
        "HUB_HYBRID_INGRESS_KEY",
        "HUB_STORAGE_WORK_KEY",
        "HUB_DIRECT_UPLOAD_GUARD_KEY",
        "HUB_DIRECT_UPLOAD_JOURNAL_KEY",
        "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID",
        "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();

    assert!(protected.require_bindings(&cfg, &existing).is_err());
    existing.push("HUB_MIRROR_GUARD_KEY".into());
    protected.require_bindings(&cfg, &existing).unwrap();
    assert!(protected.entries.is_empty());
}

#[cfg(unix)]
fn private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt as _;

    // Start traversal at the trusted current directory. Qualification sandboxes
    // may expose absolute ancestors with remapped ownership.
    let directory = tempfile::tempdir_in(".").unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[cfg(unix)]
fn secret(directory: &Path, name: &str, value: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let path = directory.join(name);
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    relative_path(&path)
}

#[cfg(unix)]
fn relative_path(path: &Path) -> PathBuf {
    path.strip_prefix(std::env::current_dir().unwrap())
        .unwrap()
        .to_owned()
}

#[test]
fn update_preserves_existing_required_secret_bindings_without_reading_values() {
    let cfg = config();
    let protected = ProtectedSecrets::read(&HybridDeploySecretFiles::default(), &cfg).unwrap();
    let existing = [
        "HUB_HYBRID_INGRESS_KEY",
        "HUB_STORAGE_WORK_KEY",
        "HUB_DIRECT_UPLOAD_GUARD_KEY",
        "HUB_DIRECT_UPLOAD_JOURNAL_KEY",
        "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID",
        "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();

    protected.require_bindings(&cfg, &existing).unwrap();

    assert!(protected.entries.is_empty());
    assert!(protected
        .require_bindings(&cfg, &existing[..existing.len() - 1])
        .is_err());
    assert!(protected.require_bindings(&cfg, &[]).is_err());
}

#[cfg(unix)]
#[test]
fn isolated_qualification_requires_existing_protected_control_secret() {
    let mut cfg = config();
    cfg.direct_upload_qualification =
        Some(crate::cloudflare::HybridDirectUploadQualificationConfig {
            maximum_provider_requests: aos_hub_core::direct_upload::WireInteger::new(8),
            maximum_object_bytes: aos_hub_core::direct_upload::WireInteger::new(1024),
        });
    let protected = ProtectedSecrets::read(&HybridDeploySecretFiles::default(), &cfg).unwrap();
    let existing = [
        "HUB_HYBRID_INGRESS_KEY",
        "HUB_STORAGE_WORK_KEY",
        "HUB_DIRECT_UPLOAD_GUARD_KEY",
        "HUB_DIRECT_UPLOAD_JOURNAL_KEY",
        "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID",
        "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    assert!(protected.require_bindings(&cfg, &existing).is_err());

    let directory = private_directory();
    let files = HybridDeploySecretFiles {
        direct_upload_conformance_key_file: Some(secret(
            directory.path(),
            "control",
            &"q".repeat(64),
        )),
        ..HybridDeploySecretFiles::default()
    };
    let protected = ProtectedSecrets::read(&files, &cfg).unwrap();
    protected.require_bindings(&cfg, &existing).unwrap();
    cfg.direct_upload_qualification = None;
    assert!(ProtectedSecrets::read(&files, &cfg).is_err());
}

#[cfg(unix)]
#[test]
fn protected_loader_refuses_reused_keys_and_nonprivate_or_symlinked_files() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = private_directory();
    let key = secret(directory.path(), "key", &"a".repeat(64));
    let mut files = HybridDeploySecretFiles {
        storage_work_key_file: Some(key.clone()),
        direct_upload_guard_key_file: Some(key.clone()),
        ..HybridDeploySecretFiles::default()
    };
    let cfg = config();

    assert!(ProtectedSecrets::read(&files, &cfg).is_err());

    files.direct_upload_guard_key_file = Some(secret(directory.path(), "guard", &"b".repeat(64)));
    ProtectedSecrets::read(&files, &cfg).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(ProtectedSecrets::read(&files, &cfg).is_err());

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = directory.path().join("link");
    symlink(std::env::current_dir().unwrap().join(&key), &link).unwrap();
    files.storage_work_key_file = Some(relative_path(&link));
    assert!(ProtectedSecrets::read(&files, &cfg).is_err());
}

#[cfg(unix)]
#[test]
fn persistent_provider_key_pair_travels_only_as_protected_secret_bindings() {
    let directory = private_directory();
    let files = HybridDeploySecretFiles {
        direct_upload_access_key_id_file: Some(secret(
            directory.path(),
            "access",
            "private-access-marker",
        )),
        direct_upload_secret_access_key_file: Some(secret(
            directory.path(),
            "secret",
            "private-secret-marker",
        )),
        ..HybridDeploySecretFiles::default()
    };
    let cfg = config();

    let protected = ProtectedSecrets::read(&files, &cfg).unwrap();
    let source = crate::cloudflare::render_hybrid_wrangler_toml(&cfg).unwrap();

    assert_eq!(
        protected
            .entries
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>(),
        [
            "HUB_DIRECT_UPLOAD_R2_ACCESS_KEY_ID",
            "HUB_DIRECT_UPLOAD_R2_SECRET_ACCESS_KEY"
        ]
    );
    assert!(!source.contains("private-access-marker"));
    assert!(!source.contains("private-secret-marker"));
    let mut incomplete = files;
    incomplete.direct_upload_secret_access_key_file = None;
    assert!(ProtectedSecrets::read(&incomplete, &cfg).is_err());
}

#[cfg(unix)]
#[test]
fn missing_or_fifo_secret_reads_fail_without_exposing_input_values() {
    let directory = private_directory();
    let fifo = directory.path().join("key.fifo");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();

    assert!(read_protected_text(&relative_path(&fifo)).is_err());

    let path = secret(directory.path(), "invalid", "private-value\u{0}marker");
    let files = HybridDeploySecretFiles {
        direct_upload_secret_access_key_file: Some(path.clone()),
        direct_upload_access_key_id_file: Some(secret(
            directory.path(),
            "access",
            "private-access",
        )),
        ..HybridDeploySecretFiles::default()
    };
    let error = match ProtectedSecrets::read(&files, &config()) {
        Ok(_) => panic!("invalid secret was accepted"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains("private-value"));
}

#[cfg(unix)]
#[test]
fn paired_native_key_files_are_exact_and_never_silently_trimmed() {
    let directory = private_directory();
    let original = "a".repeat(64);
    let path = secret(directory.path(), "guard", &original);

    assert_eq!(read_protected_text(&path).unwrap().as_str(), original);

    for changed in [
        format!("{original}\n"),
        format!(" {original}"),
        format!("{original} "),
    ] {
        std::fs::write(&path, changed).unwrap();
        assert!(read_protected_text(&path).is_err());
    }
}
