//! Checks data-only directory pin invariants without native reclamation claims.

// crucible-lint: allow panic-shortcut -- Directory identity regressions fail on the first unmet assertion and never construct native authority.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::os::unix::fs::PermissionsExt;

use super::retirement::PinnedNamespace;

#[test]
fn namespace_pin_refuses_a_replacement_directory() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("original");
    let moved = root.path().join("moved");
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pin = PinnedNamespace::new(&original.canonicalize().unwrap()).unwrap();

    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(original.join("foreign"), b"retained").unwrap();

    assert!(pin.remove().is_err());
    assert_eq!(
        std::fs::read(original.join("foreign")).unwrap(),
        b"retained"
    );
    assert!(moved.is_dir());
}

#[test]
fn namespace_pin_refuses_widened_permissions() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let pin = PinnedNamespace::new(&path).unwrap();
    std::fs::write(path.join("original"), b"retained").unwrap();

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(pin.remove().is_err());
    assert_eq!(std::fs::read(path.join("original")).unwrap(), b"retained");
}
