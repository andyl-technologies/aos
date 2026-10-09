//! Root-private physical-name regressions for an exclusively held route writer.
//!
//! These ignored fixtures create only a unique private directory under
//! `/var/lib`; they never rename or replace the production Host state root.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use aos_sandbox::{Journal, JournalLimits, RecordNamespace};

use super::{HostOpenSshAttachRouteOwnerV1, ROUTE_JOURNAL_NAME};

fn private_root() -> tempfile::TempDir {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    let root = tempfile::Builder::new()
        .prefix("aos-attach-route-names-")
        .tempdir_in("/var/lib")
        .unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn replace_with_same_bytes(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "requires an isolated root-owned /var/lib fixture"]
fn held_route_claim_rejects_same_byte_journal_and_lock_replacements() {
    let root = private_root();
    let (mut journal, _) =
        Journal::open_protected_at(root.path(), ROUTE_JOURNAL_NAME, JournalLimits::default())
            .unwrap();
    let authority = journal
        .claim_protected_authority(RecordNamespace::HostExecution)
        .unwrap();
    authority
        .validate_held_root_owned_at(root.path(), ROUTE_JOURNAL_NAME)
        .unwrap();

    for name in [
        ROUTE_JOURNAL_NAME.to_owned(),
        format!("{ROUTE_JOURNAL_NAME}.lock"),
    ] {
        let named = root.path().join(&name);
        let moved = root.path().join(format!("{name}.retained"));
        let original = fs::read(&named).unwrap();
        fs::rename(&named, &moved).unwrap();
        replace_with_same_bytes(&named, &original);

        assert!(
            authority
                .validate_held_root_owned_at(root.path(), ROUTE_JOURNAL_NAME)
                .is_err()
        );
        fs::remove_file(&named).unwrap();
        fs::rename(&moved, &named).unwrap();
        authority
            .validate_held_root_owned_at(root.path(), ROUTE_JOURNAL_NAME)
            .unwrap();
    }
}

#[test]
#[ignore = "requires an isolated root-owned /var/lib fixture"]
fn held_route_claim_rejects_an_orphaned_parent_with_same_byte_named_files() {
    let fixture = private_root();
    let root = fixture.path().join("host-state");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let (mut journal, _) =
        Journal::open_protected_at(&root, ROUTE_JOURNAL_NAME, JournalLimits::default()).unwrap();
    let authority = journal
        .claim_protected_authority(RecordNamespace::HostExecution)
        .unwrap();
    let moved = fixture.path().join("retained-host-state");
    fs::rename(&root, &moved).unwrap();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    for name in [
        ROUTE_JOURNAL_NAME.to_owned(),
        format!("{ROUTE_JOURNAL_NAME}.lock"),
    ] {
        replace_with_same_bytes(&root.join(&name), &fs::read(moved.join(&name)).unwrap());
    }

    assert!(
        authority
            .validate_held_root_owned_at(&root, ROUTE_JOURNAL_NAME)
            .is_err()
    );
    fs::remove_file(root.join(ROUTE_JOURNAL_NAME)).unwrap();
    fs::remove_file(root.join(format!("{ROUTE_JOURNAL_NAME}.lock"))).unwrap();
    fs::remove_dir(&root).unwrap();
    fs::rename(&moved, &root).unwrap();
    authority
        .validate_held_root_owned_at(&root, ROUTE_JOURNAL_NAME)
        .unwrap();
}

#[test]
#[ignore = "requires an isolated root-owned /var/lib fixture"]
fn ticket_presence_selector_rejects_a_foreign_named_route_root() {
    let root = private_root();
    let (journal, _) =
        Journal::open_protected_at(root.path(), ROUTE_JOURNAL_NAME, JournalLimits::default())
            .unwrap();
    let mut owner = HostOpenSshAttachRouteOwnerV1 { journal };

    // Even an advisory selector must not branch on another directory's cached
    // snapshot. This fixture never opens or modifies the production Host root.
    assert!(owner.has_original_ticket_binding_v2([1; 16]).is_err());
}
