//! Tests for expose manifest validation and compilation of mandatory-access-control artifacts.

use super::{
    publish_selinux_identifier_for_label, read_publish_expose_manifest,
    read_publish_manifest_digest,
};
use crate::registry_ops::test_support::write_publish_selinux_artifacts;
use std::fs;
use tempfile::TempDir;

#[test]
fn read_publish_expose_manifest_accepts_renderer_mac_manifest() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("manifest.json");
    let mac = serde_json::json!({
        "version": 1,
        "package": "webapp",
        "backend": "selinux",
        "securityLabel": "aos-pkg-webapp",
        "defaultDeny": true,
        "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
    });
    let manifest = serde_json::json!({
        "expose": {
            "target": "aos-pkg-webapp.target",
            "units": ["webapp.service"],
        },
        "kernel": {
            "modules": [],
        },
        "firewall": {
            "enabled": false,
        },
        "mac": mac,
        "confinement": {
            "class": "sandboxed",
            "label": "sandboxed",
            "holes": [],
        },
        "permissions": {
            "security-label": "aos-pkg-webapp",
            "confinement": {
                "class": "sandboxed",
                "label": "sandboxed",
                "holes": [],
            },
        },
    });
    fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();
    fs::write(
        tmp.path().join("mac-profile.json"),
        serde_json::to_string(&manifest["mac"]).unwrap(),
    )
    .unwrap();
    write_publish_selinux_artifacts(tmp.path(), "aos-pkg-webapp");

    let parsed = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap();
    let mac = parsed.mac.as_ref().unwrap();

    assert_eq!(mac.backend, "selinux");
    assert_eq!(mac.security_label, "aos-pkg-webapp");
    assert_eq!(
        mac.profile_path.as_deref(),
        Some("mac/selinux/aos_x2dpkg_x2dwebapp.pp")
    );
}

#[test]
fn read_publish_expose_manifest_rejects_target_bound_to_other_package() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("manifest.json");
    let manifest = serde_json::json!({
        "expose": {
            "target": "aos-pkg-other.target",
            "units": ["webapp.service"],
        },
        "permissions": {},
    });
    fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

    assert!(
        format!("{err:#}").contains("must equal aos-pkg-webapp.target"),
        "{err:#}"
    );
}

#[test]
fn read_publish_manifest_digest_tracks_manifest_bytes() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("manifest.json");
    fs::write(&path, br#"{"permissions":{"network":"private"}}"#).unwrap();
    let first = read_publish_manifest_digest(&path).unwrap();

    fs::write(&path, br#"{"permissions":{"network":"host"}}"#).unwrap();
    let second = read_publish_manifest_digest(&path).unwrap();

    assert_eq!(
        first,
        crate::package_attestation::package_manifest_digest_bytes(
            br#"{"permissions":{"network":"private"}}"#
        )
    );
    assert_ne!(first, second);
}

#[test]
fn publish_selinux_identifiers_escape_label_punctuation_without_collisions() {
    let labels = ["a.b", "a-b", "a_b", "a+b", "a=b"];
    let identifiers = labels
        .iter()
        .map(|label| publish_selinux_identifier_for_label(label))
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(identifiers.len(), labels.len());
    assert_eq!(
        publish_selinux_identifier_for_label("aos-pkg-webapp"),
        "aos_x2dpkg_x2dwebapp"
    );
    assert_eq!(
        publish_selinux_identifier_for_label("1webapp"),
        "aos_pkg_1webapp"
    );
}

#[test]
fn read_publish_expose_manifest_rejects_mac_profile_payload_mismatch() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("manifest.json");
    let mac = serde_json::json!({
        "version": 1,
        "package": "webapp",
        "backend": "selinux",
        "securityLabel": "aos-pkg-webapp",
        "defaultDeny": true,
        "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
    });
    let manifest = serde_json::json!({
        "expose": {
            "target": "aos-pkg-webapp.target",
            "units": ["webapp.service"],
        },
        "mac": mac,
        "permissions": {
            "security-label": "aos-pkg-webapp",
            "confinement": {
                "class": "sandboxed",
                "label": "sandboxed",
                "holes": [],
            },
        },
    });
    fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();
    fs::write(
        tmp.path().join("mac-profile.json"),
        serde_json::to_string(&manifest["mac"]).unwrap(),
    )
    .unwrap();
    write_publish_selinux_artifacts(tmp.path(), "aos-pkg-webapp");
    fs::write(
        tmp.path().join("mac/selinux/aos_x2dpkg_x2dwebapp.pp"),
        b"permissive compiled policy",
    )
    .unwrap();

    let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

    assert!(
        format!("{err:#}").contains("does not match the validated SELinux source"),
        "{err:?}"
    );
}

#[test]
fn read_publish_expose_manifest_rejects_missing_mac_artifact() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("manifest.json");
    let manifest = serde_json::json!({
        "expose": {
            "target": "aos-pkg-webapp.target",
            "units": ["webapp.service"],
        },
        "mac": {
            "version": 1,
            "package": "webapp",
            "backend": "selinux",
            "securityLabel": "aos-pkg-webapp",
            "defaultDeny": true,
            "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
        },
        "permissions": {
            "security-label": "aos-pkg-webapp",
            "confinement": {
                "class": "sandboxed",
                "label": "sandboxed",
                "holes": [],
            },
        },
    });
    fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();

    let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

    assert!(format!("{err:#}").contains("validating MAC profile artifact for package 'webapp'"));
}

#[cfg(unix)]
#[test]
fn read_publish_expose_manifest_rejects_mac_profile_parent_symlink() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("manifest.json");
    let mac = serde_json::json!({
        "version": 1,
        "package": "webapp",
        "backend": "selinux",
        "securityLabel": "aos-pkg-webapp",
        "defaultDeny": true,
        "profilePath": "mac/selinux/aos_x2dpkg_x2dwebapp.pp",
    });
    let manifest = serde_json::json!({
        "expose": {
            "target": "aos-pkg-webapp.target",
            "units": ["webapp.service"],
        },
        "mac": mac,
        "permissions": {
            "security-label": "aos-pkg-webapp",
            "confinement": {
                "class": "sandboxed",
                "label": "sandboxed",
                "holes": [],
            },
        },
    });
    fs::write(&path, serde_json::to_string(&manifest).unwrap()).unwrap();
    fs::write(
        tmp.path().join("mac-profile.json"),
        serde_json::to_string(&manifest["mac"]).unwrap(),
    )
    .unwrap();
    let external_mac = tmp.path().join("external-mac");
    let external_profile = external_mac.join("selinux/aos_x2dpkg_x2dwebapp.pp");
    fs::create_dir_all(external_profile.parent().unwrap()).unwrap();
    fs::write(&external_profile, b"compiled-policy").unwrap();
    std::os::unix::fs::symlink(&external_mac, tmp.path().join("mac")).unwrap();

    let err = read_publish_expose_manifest(path.to_str().unwrap(), "webapp").unwrap_err();

    assert!(
        format!("{err:#}").contains("not a non-symlink directory"),
        "{err:?}"
    );
}
