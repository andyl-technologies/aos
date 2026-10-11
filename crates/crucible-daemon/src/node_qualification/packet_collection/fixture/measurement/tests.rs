//! Exercises genuine file bytes with finite streaming measurement controls.

// crucible-lint: allow panic-shortcut -- These file-measurement controls use assertions as their oracle.
#![allow(clippy::unwrap_used)]

use super::*;
use crucible_node_contract::canonical;

#[test]
fn streamed_identity_matches_original_cnp_framing_and_refuses_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("original-public-source");
    let bytes = vec![0x81; 65_537];
    std::fs::write(&path, &bytes).unwrap();
    let expected = canonical::content_ref(&bytes, "application/octet-stream").unwrap();

    assert!(measure(&path, &expected).is_ok());
    std::fs::write(&path, vec![0x82; bytes.len()]).unwrap();

    assert!(measure(&path, &expected).is_err());
}

#[test]
fn overwide_or_wrong_extent_refuses_before_file_open() {
    let mut expected = canonical::content_ref(b"original", "text/plain").unwrap();
    let unavailable = Path::new("/unavailable-packet-measurement-control");
    expected.length = U64::new(MAXIMUM_ARTIFACT + 1);

    assert!(matches!(
        measure(unavailable, &expected),
        Err(QualificationError::Refused(_))
    ));
    expected.length = U64::new(0);
    assert!(matches!(
        measure(unavailable, &expected),
        Err(QualificationError::Refused(_))
    ));
}
