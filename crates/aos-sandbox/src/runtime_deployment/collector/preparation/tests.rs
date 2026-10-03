//! UNRUN passive root DATA; no detached mount or deployment permit is fabricated.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use aos_sandbox_agent::guest_root_tree::measure_offline_guest_root_template_v1;

use super::*;

#[test]
fn unrun_specimen_digest_pin_is_exact_lowercase_full_length_data() {
    let mut digest = [0; 32];
    digest[0] = 0xaf;
    digest[31] = 0x19;
    let encoded = canonical_digest_pin(digest);
    let expected = format!("af{}19\n", "0".repeat(60));
    assert_eq!(encoded, expected.as_bytes());
    assert_eq!(encoded.len(), 65);
    assert_ne!(encoded, expected.to_uppercase().as_bytes());
    assert_ne!(encoded, expected.trim_end().as_bytes());
    assert_ne!(encoded, canonical_digest_pin([0; 32]));
}

#[test]
fn unrun_actual_shared_complete_tree_measurement_includes_init_link_bytes_and_modes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::create_dir_all(root.join("usr/lib/systemd")).unwrap();
    fs::create_dir(root.join("sbin")).unwrap();
    let executable = root.join("usr/lib/systemd/systemd");
    fs::write(&executable, b"fixed specimen image").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).unwrap();
    symlink("../usr/lib/systemd/systemd", root.join("sbin/init")).unwrap();

    // Offline measurement is deliberately not root ownership or Ready. The
    // production passive owner calls the root-enforcing comparison entrypoint.
    let original = measure_offline_guest_root_template_v1(&root).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&executable, b"changed specimen image").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o555)).unwrap();
    let changed_bytes = measure_offline_guest_root_template_v1(&root).unwrap();
    assert_ne!(original, changed_bytes);

    fs::set_permissions(&executable, fs::Permissions::from_mode(0o444)).unwrap();
    let changed_mode = measure_offline_guest_root_template_v1(&root).unwrap();
    assert_ne!(changed_bytes, changed_mode);

    fs::remove_file(root.join("sbin/init")).unwrap();
    symlink("../usr/lib/systemd/other", root.join("sbin/init")).unwrap();
    let changed_link = measure_offline_guest_root_template_v1(&root).unwrap();
    assert_ne!(changed_mode, changed_link);

    let other = root.join("sbin/other-init");
    symlink("../usr/lib/systemd/systemd", &other).unwrap();
    let added_entry = measure_offline_guest_root_template_v1(&root).unwrap();
    assert_ne!(changed_link, added_entry);

    fs::set_permissions(&executable, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(measure_offline_guest_root_template_v1(&root).is_err());
}
