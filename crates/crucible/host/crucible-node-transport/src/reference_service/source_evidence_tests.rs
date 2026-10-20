//! Selected role and finite pre-effect credit counterexamples; no source authority.

// crucible-lint: allow panic-shortcut -- Exact role/credit fixture mismatches invalidate the test.
#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn two_original_media_roles_keep_exact_bytes_and_independent_transfer_keys() {
    let mut evidence = SourceEvidence::new(1024).unwrap();
    let json = canonical::content_ref(b"{}", "application/json").unwrap();
    let octets = canonical::content_ref(b"{}", "application/octet-stream").unwrap();

    evidence.store(json.clone(), b"{}".to_vec()).unwrap();
    evidence.store(octets.clone(), b"{}".to_vec()).unwrap();

    assert_eq!(evidence.content(&json), Some(b"{}".as_slice()));
    assert_eq!(evidence.content(&octets), Some(b"{}".as_slice()));
    assert_ne!(typed_key(&json).unwrap(), typed_key(&octets).unwrap());
    assert_eq!(evidence.bytes, 4);
    assert_eq!(evidence.objects.len(), 2);
    assert!(evidence.store(json.clone(), b"[]".to_vec()).is_err());
    assert_eq!(evidence.objects.len(), 2);
    let mut unretained_role = json;
    unretained_role.media_type = "text/plain".into();
    assert!(evidence.content(&unretained_role).is_none());
}

#[test]
fn complete_window_credit_refuses_before_native_receipt_allocation() {
    let required = NATIVE_WINDOW_BYTES + PUBLIC_WINDOW_BYTES;
    let mut evidence = SourceEvidence::new(required - 1).unwrap();
    assert!(evidence.reserve_native_window().is_err());
    assert_eq!(evidence.reserved_native_bytes, 0);
    assert_eq!(evidence.reserved_native_objects, 0);

    let mut evidence = SourceEvidence::new(required).unwrap();
    evidence.reserve_native_window().unwrap();
    let original = vec![7; PUBLIC_WINDOW_BYTES];
    let reference = canonical::content_ref(&original, "application/octet-stream").unwrap();
    evidence.store(reference.clone(), original).unwrap();
    assert!(evidence.reserve_native_window().is_err());
    assert_eq!(evidence.reserved_native_bytes, NATIVE_WINDOW_BYTES);
    assert_eq!(
        evidence.content(&reference).unwrap().len(),
        PUBLIC_WINDOW_BYTES
    );
}
