//! Operational auditor receipt checks beneath an explicitly source-built shell.

// Fixture assertions exercise process I/O and locale isolation, not native
// preservation qualification or an installed profile certificate.
// crucible-lint: allow panic-shortcut -- These closure locale tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use super::*;

#[test]
#[ignore = "requires CRUCIBLE_AOS_BASH and parent LC_ALL=C.UTF-8"]
fn inherited_uninstalled_locale_cannot_corrupt_original_auditor_receipt() {
    assert_eq!(std::env::var("LC_ALL").unwrap(), "C.UTF-8");
    let shell = PathBuf::from(std::env::var_os("CRUCIBLE_AOS_BASH").expect("source-built bash"));
    assert!(shell.is_absolute());
    assert!(shell.is_file());
    let root = std::env::temp_dir().join(format!("crucible-auditor-locale-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let auditor_path = root.join("auditor");
    let script = format!(
        "#!{}\nIFS= read -r original || :\nprintf '{{\"locale\":\"%s\",\"original\":%s}}' \"$LC_ALL\" \"$original\"\n",
        shell.display()
    );
    fs::write(&auditor_path, script).unwrap();
    fs::set_permissions(&auditor_path, fs::Permissions::from_mode(0o700)).unwrap();
    let auditor = Gem5LaunchArtifact {
        content: crate::gem5::images::measure_file(&auditor_path).unwrap(),
        path: auditor_path,
    };
    let original = json!({"schema":"locale-probe.v1","nonce":"unchanged-original-input"});

    let receipt = execute_auditor(&auditor, &original, Duration::from_secs(10)).unwrap();
    let parsed = canonical::parse_json(&receipt, MAX_AUDIT_BYTES).unwrap();

    assert_eq!(parsed, json!({"locale":"C","original":original}));
    assert!(!String::from_utf8(receipt).unwrap().contains("setlocale"));
    fs::remove_dir_all(root).unwrap();
}
