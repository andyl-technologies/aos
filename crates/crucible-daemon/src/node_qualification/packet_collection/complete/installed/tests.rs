//! Exercises the production installer with real files and unqualified declarations.
//!
//! Controls measure the actual test ELF and source fixtures, read entropy and
//! reserve local socket/eventfd inputs. They start no Child, worker or protocol.

use super::*;
use crucible_node_contract::canonical;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn private_directory() -> tempfile::TempDir {
    // The installer requires an owner-only parent; tempfile defaults depend on
    // the process umask and do not establish that precondition.
    let directory = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let metadata = std::fs::symlink_metadata(directory.path()).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.mode() & 0o777, 0o700);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(
        std::fs::canonicalize(directory.path()).unwrap(),
        directory.path()
    );
    directory
}

fn pinned(
    directory: &std::path::Path,
    value: &serde_json::Value,
) -> InstalledCompleteSceneManifest {
    let bytes = canonical::canonical_json(value).unwrap();
    let expected = canonical::content_ref(&bytes, "application/json").unwrap();
    let path = directory.join("installation.json");
    std::fs::write(&path, &bytes).unwrap();
    InstalledCompleteSceneManifest::new(path, expected).unwrap()
}

#[test]
fn actual_installer_retains_source_host_registry_and_ready_births_without_child() {
    let (_source, value) = super::super::tests::installed_scene_declaration();
    let directory = private_directory();
    let manifest = pinned(directory.path(), &value);
    let mut installed =
        InstalledCompleteScene::install(manifest, directory.path().join("scene")).unwrap();
    let incoming = installed.incoming.as_ref().unwrap();
    assert!(incoming.roles.iter().all(Option::is_some));
    assert!(incoming.content.is_some());
    assert_eq!(incoming.runtime_limits.maximum_nodes, 4);
    assert_eq!(incoming.runtime_limits.maximum_owners, 4);
    assert!(incoming.launches.iter().all(|one| one.as_ref().is_some_and(
        |input| input.slot.is_none()
            && input.bootstrap_reader.is_some()
            && input.bootstrap_writer.is_some()
    )));
    assert!(!installed.attempted);
    assert!(!installed.retired);
    installed.retire().unwrap();
    installed.retire().unwrap();
    assert!(installed.is_reclaimed());
    assert!(installed.poll_reclamation().unwrap());
    assert!(installed.prepare().is_err());
}

#[test]
fn changed_package_bytes_and_accepted_fields_refuse_before_namespace_creation() {
    let (_source, mut value) = super::super::tests::installed_scene_declaration();
    let directory = private_directory();
    let manifest = pinned(directory.path(), &value);
    std::fs::write(&manifest.path, b"{}").unwrap();
    let target = directory.path().join("changed");
    assert!(InstalledCompleteScene::install(manifest, target.clone()).is_err());
    assert!(!target.exists());

    value["accepted"] = serde_json::json!(true);
    let manifest = pinned(directory.path(), &value);
    let target = directory.path().join("forged");
    assert!(InstalledCompleteScene::install(manifest, target.clone()).is_err());
    assert!(!target.exists());
}

#[test]
fn changed_declared_source_and_duplicate_content_refuse_installation() {
    let (_source, mut value) = super::super::tests::installed_scene_declaration();
    let directory = private_directory();
    value["measurements"][0]["sources"][0]["content"]["hash"]["digest"] =
        serde_json::json!("0".repeat(64));
    let manifest = pinned(directory.path(), &value);
    let target = directory.path().join("source-drift");
    assert!(InstalledCompleteScene::install(manifest, target.clone()).is_err());
    assert!(!target.exists());

    let (_source, mut value) = super::super::tests::installed_scene_declaration();
    let duplicate = value["content"][0].clone();
    value["content"].as_array_mut().unwrap().push(duplicate);
    let manifest = pinned(directory.path(), &value);
    let target = directory.path().join("duplicate");
    assert!(InstalledCompleteScene::install(manifest, target.clone()).is_err());
    assert!(!target.exists());
}

#[test]
fn unsupported_profile_refuses_before_private_socket_acquisition() {
    let (_source, mut value) = super::super::tests::installed_scene_declaration();
    let directory = private_directory();
    value["participants"][0]["capture_profile"] = serde_json::to_value(
        crucible_node_provider::reference_packet::service::PacketNative5CaptureProfile::OriginalArrays6,
    ).unwrap();
    let manifest = pinned(directory.path(), &value);
    let target = directory.path().join("unsupported");
    assert!(InstalledCompleteScene::install(manifest, target.clone()).is_err());
    assert!(!target.exists());
}

impl InstalledCompleteScene {
    /// Visits a real installed capsule restricted to its spent-entry guard.
    pub(crate) fn with_spent_prepare_entry_for_test(visit: impl FnOnce(Self)) {
        let (_source, value) = super::super::tests::installed_scene_declaration();
        let directory = private_directory();
        let manifest = pinned(directory.path(), &value);
        let mut installed = Self::install(manifest, directory.path().join("scene")).unwrap();
        // Restrict the actual pre-Child capsule to exercise its repeated-entry
        // refusal. This does not model a successful native preparation.
        installed.attempted = true;
        visit(installed);
    }
}

#[test]
fn started_prepare_failure_retires_without_retry_or_losing_original_holder() {
    let (_source, value) = super::super::tests::installed_scene_declaration();
    let directory = private_directory();
    let manifest = pinned(directory.path(), &value);
    let mut installed =
        InstalledCompleteScene::install(manifest, directory.path().join("scene")).unwrap();
    let original = Rc::clone(&installed.original);
    // The real stage retains these owners, then refuses this invalid geometry
    // before supervisor reservation or any Child construction.
    installed
        .incoming
        .as_mut()
        .unwrap()
        .runtime_limits
        .maximum_nodes = 0;

    assert!(installed.prepare().is_err());
    assert!(installed.attempted);
    assert!(installed.retired);
    assert!(installed.incoming.is_none());
    assert!(Rc::ptr_eq(&original, &installed.original));
    assert!(!installed.is_reclaimed());

    assert!(installed.prepare().is_err());
    assert!(installed.retired);
    assert!(installed.incoming.is_none());
    assert!(Rc::ptr_eq(&original, &installed.original));
    installed.retire().unwrap();
}

#[test]
fn changed_source_file_refuses_the_unchanged_pinned_manifest() {
    let (_source, value) = super::super::tests::installed_scene_declaration();
    let directory = private_directory();
    let manifest = pinned(directory.path(), &value);
    let manifest_bytes = std::fs::read(&manifest.path).unwrap();
    let source = &value["measurements"][0]["sources"][0];
    let path = PathBuf::from(source["path"].as_str().unwrap());
    let expected: ContentRef = serde_json::from_value(source["content"].clone()).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    expected.verify(&bytes).unwrap();
    // Only a disposable source fixture is changed, never the measured test ELF.
    bytes[0] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    assert!(expected.verify(&bytes).is_err());

    assert!(
        InstalledCompleteScene::install(manifest.clone(), directory.path().join("drift")).is_err()
    );
    assert_eq!(std::fs::read(&manifest.path).unwrap(), manifest_bytes);
    // Namespace absence is not used as an oracle for acquisition ordering.
}

#[test]
fn actual_installer_rejects_public_parent_and_accepts_private_parent() {
    let (_source, value) = super::super::tests::installed_scene_declaration();
    let directory = private_directory();
    let manifest = pinned(directory.path(), &value);
    let target = directory.path().join("scene");

    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let metadata = std::fs::symlink_metadata(directory.path()).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.mode() & 0o777, 0o755);
    assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
    assert_eq!(
        std::fs::canonicalize(directory.path()).unwrap(),
        directory.path()
    );
    assert!(InstalledCompleteScene::install(manifest.clone(), target.clone()).is_err());
    assert!(!target.exists());

    // The same pin, source files, owner and target are accepted after changing
    // only this disposable parent's mode to the production requirement.
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        std::fs::symlink_metadata(directory.path()).unwrap().mode() & 0o777,
        0o700,
    );
    let mut installed = InstalledCompleteScene::install(manifest, target).unwrap();
    assert!(!installed.attempted);
    assert!(!installed.retired);
    installed.retire().unwrap();
}
