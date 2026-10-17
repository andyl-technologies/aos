//! Original byte seals, closed directory inventories and normal relocation paths.

// Test panics identify an unexpected relaxation of native custody requirements.
// crucible-lint: allow panic-shortcut -- These saved files manifest tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::{AtomicU64, Ordering},
};

use crucible_node_contract::canonical;

use super::*;

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "crucible-gem5-saved-copy-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture(directory: &Path, name: &str, bytes: &[u8]) -> Gem5LaunchArtifact {
    let path = directory.join(name);
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    Gem5LaunchArtifact {
        path,
        content: canonical::content_ref(bytes, "application/octet-stream").unwrap(),
    }
}

#[test]
fn native_sha256_and_canonical_seal_cover_the_same_original_stream() {
    let directory = TestRoot::new();
    let original = fixture(directory.path(), "guest.elf_1", b"abc");

    assert_eq!(
        hash_sealed_file(&original).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let empty = fixture(directory.path(), "stats.txt_2", b"");
    assert_eq!(
        hash_sealed_file(&empty).unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn altered_bytes_and_foreign_typed_metadata_refuse_before_native_reconstruction() {
    let directory = TestRoot::new();
    let mut original = fixture(directory.path(), "guest.elf_1", b"abc");
    fs::write(&original.path, b"abd").unwrap();
    assert!(hash_sealed_file(&original).is_err());

    fs::write(&original.path, b"abc").unwrap();
    original.content.media_type = "application/json".to_owned();
    assert!(hash_sealed_file(&original).is_err());
}

#[test]
fn native_saved_copy_cannot_alias_symlinks_or_shared_file_inodes() {
    let directory = TestRoot::new();
    let original = fixture(directory.path(), "guest.elf_1", b"abc");
    let mut alias = original.clone();
    alias.path = directory.path().join("alias");
    symlink(&original.path, &alias.path).unwrap();
    assert!(hash_sealed_file(&alias).is_err());

    fs::remove_file(&alias.path).unwrap();
    fs::hard_link(&original.path, &alias.path).unwrap();
    assert!(hash_sealed_file(&alias).is_err());
    assert!(hash_sealed_file(&original).is_err());
}

#[test]
fn extra_files_and_nested_entries_cannot_expand_the_complete_signed_roster() {
    let directory = TestRoot::new();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let original = fixture(directory.path(), "guest.elf_1", b"abc");
    let files = BTreeMap::from([("guest.elf_1".to_owned(), &original)]);

    check_directory_roster(directory.path(), &files).unwrap();
    let extra = directory.path().join("extra");
    fs::write(&extra, b"unowned").unwrap();
    assert!(check_directory_roster(directory.path(), &files).is_err());

    fs::remove_file(extra).unwrap();
    fs::create_dir(directory.path().join("nested")).unwrap();
    assert!(check_directory_roster(directory.path(), &files).is_err());
}

#[test]
fn old_roots_are_inert_text_and_ambiguous_paths_cannot_enter_the_native_roster() {
    let original = Path::new("/historical/source-already-removed/ckpt_owner_files");
    assert_eq!(root_text(original).unwrap(), original.to_str().unwrap());
    for root in ["/", "relative", "/a/../b", "/a//b", "/a/./b", "/a\nb"] {
        assert!(root_text(Path::new(root)).is_err(), "{root}");
    }
    for leaf in ["../escape", "nested/file", ".", "bad\tname", "bad\nname"] {
        assert!(leaf_text(Path::new(leaf)).is_err(), "{leaf}");
    }
    assert_eq!(leaf_text(Path::new("stats.txt_1")).unwrap(), "stats.txt_1");
}
