//! Exercises actual install measurements and closed input refusals without authority.

use super::*;
use std::io::{Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn temporary_file() -> File {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "crucible-source-birth-install-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    // Linux retains the original descriptor; the fixture leaves no name or
    // scratch tree behind, including an assertion failure later in the test.
    std::fs::remove_file(path).unwrap();
    file
}

#[test]
fn a_same_opened_original_must_match_the_independent_expected_content() {
    let mut original = temporary_file();
    original.write_all(b"original executable").unwrap();
    let content = crucible_node_format::canonical::content_ref(
        b"original executable",
        "application/octet-stream",
    )
    .unwrap();
    let mut measured = 0;
    measure(&original, &content, &mut measured).unwrap();
    assert_eq!(measured, content.length.get());

    original.seek(SeekFrom::Start(0)).unwrap();
    original.write_all(b"replaced executable").unwrap();
    assert_eq!(
        measure(&original, &content, &mut 0),
        Err(RuntimeError::ForeignAuthority)
    );
}

#[test]
fn claimed_hash_domain_algorithm_and_hex_cannot_rebind_the_installed_operand() {
    let content =
        crucible_node_format::canonical::content_ref(b"measured", "application/octet-stream")
            .unwrap();
    let expected = *blob_hash(b"measured").as_bytes();
    assert_eq!(digest(&content.hash).unwrap(), expected);
    for (algorithm, domain, text) in [
        ("sha256", "cnp.blob.v1", content.hash.digest.clone()),
        ("blake3-256", "foreign", content.hash.digest.clone()),
        ("blake3-256", "cnp.blob.v1", "A".repeat(64)),
        ("blake3-256", "cnp.blob.v1", "0".repeat(63)),
    ] {
        assert_eq!(
            digest(&HashRef {
                algorithm: algorithm.into(),
                domain: domain.into(),
                digest: text
            }),
            Err(RuntimeError::InvalidReceipt)
        );
    }
}

#[test]
fn roots_are_exact_store_occurrences_and_never_broad_or_normalized_aliases() {
    let path = Path::new("/nix/store/00000000000000000000000000000000-worker/bin/worker");
    assert_eq!(
        store_root(path).unwrap(),
        PathBuf::from("/nix/store/00000000000000000000000000000000-worker")
    );
    for invalid in [
        "/",
        "/nix/store",
        "/nix/store/short-worker",
        "/nix/store/00000000000000000000000000000000-worker/../foreign",
        "/nix/store/00000000000000000000000000000000-worker//bin",
    ] {
        assert!(store_root(Path::new(invalid)).is_err());
    }
}

#[test]
fn a_measured_intermediate_link_is_expanded_before_following_parent_segments() {
    let root = PathBuf::from("/nix/store/00000000000000000000000000000000-worker");
    let content =
        crucible_node_format::canonical::content_ref(b"file", "application/octet-stream").unwrap();
    let entries = [
        TreeEntry::Directory {
            path: root.clone(),
            mode: 0o555,
        },
        TreeEntry::Directory {
            path: root.join("actual"),
            mode: 0o555,
        },
        TreeEntry::Directory {
            path: root.join("actual/inside"),
            mode: 0o555,
        },
        TreeEntry::Symlink {
            path: root.join("route"),
            target: "actual/inside".into(),
        },
        TreeEntry::File {
            path: root.join("actual/file"),
            mode: 0o444,
            content,
        },
    ];
    let roster = entries
        .iter()
        .map(|entry| (entry.path().to_path_buf(), entry))
        .collect();
    assert_eq!(
        resolve(&root.join("route/../file"), &roster, &[root.clone()]).unwrap(),
        root.join("actual/file")
    );
    assert!(resolve(&root.join("route/../../foreign"), &roster, &[root]).is_err());
}
