//! Checks the real current-executable component without inventing Source authority.
//!
//! The expected reference here is a test measurement for the File helper only.
//! Production uses the independently pinned and parent-authenticated host ref.

use super::*;
use crucible_node_format::{HashRef, U64};
use std::io::Read;
use std::os::fd::AsRawFd;

fn current_host() -> ContentRef {
    let mut file = File::open("/proc/self/exe").unwrap();
    let length = file.metadata().unwrap().len();
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(&11u32.to_be_bytes());
    hash.update(b"cnp.blob.v1");
    hash.update(&length.to_be_bytes());
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    ContentRef {
        hash: HashRef {
            algorithm: "blake3-256".into(),
            domain: "cnp.blob.v1".into(),
            digest: hash.finalize().to_hex().to_string(),
        },
        length: U64::new(length),
        media_type: "application/octet-stream".into(),
    }
}

#[test]
fn actual_file_seed_matches_quoted_clones_and_refuses_repeated_preparation() {
    let host = current_host();
    let private_launch = Id::new("private-seed-component-control").unwrap();
    let row =
        OriginalImport18PrivateSeed::construction_data(&host, &private_launch, usize::MAX).unwrap();
    let exact = *row.iter().max().unwrap();
    assert_eq!(
        OriginalImport18PrivateSeed::construction_data(&host, &private_launch, exact).unwrap(),
        row
    );
    assert!(
        OriginalImport18PrivateSeed::construction_data(&host, &private_launch, exact - 1).is_err()
    );
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(&host, &private_launch).unwrap();
    seed.authenticate().unwrap();
    assert_eq!(seed.known_backing().unwrap(), row[0]);
    let original_fd = seed.file.as_ref().unwrap().as_raw_fd();
    let original_birth = seed.birth_id;

    assert_eq!(
        seed.prepare(&host, &private_launch),
        Err(RuntimeError::DuplicateOperation)
    );
    assert_eq!(seed.file.as_ref().unwrap().as_raw_fd(), original_fd);
    assert_eq!(seed.birth_id, original_birth);
}

#[test]
fn wrong_expected_host_keeps_first_file_prefix_and_spent_failure() {
    let mut host = current_host();
    host.length = U64::new(host.length.get() + 1);
    let private_launch = Id::new("private-seed-refusal-control").unwrap();
    let mut seed = OriginalImport18PrivateSeed::empty();
    assert!(seed.prepare(&host, &private_launch).is_err());
    assert!(seed.started && !seed.complete);
    assert!(matches!(seed.failure, Some(RuntimeError::ForeignAuthority)));
    assert!(seed.file.is_some() && seed.revision.is_some());
    assert!(seed.host.is_some() && seed.private_launch.is_some());
    assert!(seed.birth_id.is_none());
    assert_eq!(seed.key, [0; 32]);
    let fd = seed.file.as_ref().unwrap().as_raw_fd();
    assert_eq!(
        seed.prepare(&current_host(), &private_launch),
        Err(RuntimeError::DuplicateOperation)
    );
    assert_eq!(seed.file.as_ref().unwrap().as_raw_fd(), fd);
    assert!(matches!(seed.failure, Some(RuntimeError::ForeignAuthority)));
    assert!(seed.known_backing().unwrap() > 0);
}

#[test]
fn retained_original_file_authentication_rejects_foreign_descriptor() {
    let host = current_host();
    let private_launch = Id::new("private-seed-file-control").unwrap();
    let mut seed = OriginalImport18PrivateSeed::empty();
    seed.prepare(&host, &private_launch).unwrap();
    let path = std::env::temp_dir().join(format!(
        "crucible-private-seed-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let foreign = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    std::fs::remove_file(path).unwrap();
    let original = seed.file.replace(foreign);
    assert_eq!(seed.authenticate(), Err(RuntimeError::ForeignAuthority));
    seed.file = original;
    seed.authenticate().unwrap();
}
