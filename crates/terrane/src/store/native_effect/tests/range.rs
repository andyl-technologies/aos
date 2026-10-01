//! Exercises actual descriptor-bound range reads against complete preimages.

use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

fn request(held: &HeldLock, path: &std::path::Path, start: u64, bytes: &[u8]) -> NativeFsEffect {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    let mut request = effect(
        held,
        Plan::ProbeRange {
            path: path.to_owned(),
            start,
            expected: bytes.to_vec(),
        },
    );
    request.preimages.push(ExactRead {
        path: path.to_owned(),
        expected: Some(std::fs::read(path).unwrap()),
        identity: Some((metadata.dev(), metadata.ino())),
        metadata: Some(MetadataStamp::checked(&metadata).unwrap()),
        policy: FencePolicy::ProtectedRecord {
            owner: metadata.uid(),
        },
        owner: metadata.uid(),
        parents: parents(path),
    });
    request
}

#[test]
fn captured_range_reads_exact_bytes_at_nonzero_offset() {
    let (root, held) = fixture();
    let path = root.join("record");
    std::fs::write(&path, b"canonical record").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    request(&held, &path, 10, b"record")
        .execute_inline()
        .unwrap();

    assert_eq!(std::fs::read(&path).unwrap(), b"canonical record");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn captured_range_refuses_bytes_outside_complete_preimage() {
    let (root, held) = fixture();
    let path = root.join("record");
    std::fs::write(&path, b"canonical record").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    for (start, bytes) in [(10, b"absent".as_slice()), (16, b"beyond".as_slice())] {
        assert!(
            request(&held, &path, start, bytes)
                .execute_inline()
                .is_err()
        );
    }

    assert_eq!(std::fs::read(&path).unwrap(), b"canonical record");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn captured_range_refuses_missing_complete_preimage() {
    let (root, held) = fixture();
    let path = root.join("record");
    std::fs::write(&path, b"canonical record").unwrap();

    let request = effect(
        &held,
        Plan::ProbeRange {
            path: path.clone(),
            start: 0,
            expected: b"c".to_vec(),
        },
    );
    assert!(request.execute_inline().is_err());

    assert_eq!(std::fs::read(&path).unwrap(), b"canonical record");
    drop(held);
    std::fs::remove_dir_all(root).unwrap();
}
