//! Inert terminal-seal framing controls; no native source or restored authority.

// crucible-lint: allow panic-shortcut -- These parser tests deliberately panic on invalid fixtures or failed invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::OriginalTerminalControlPark;

fn fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut park = b"DCPPARK1".to_vec();
    for value in [4242u64, 4243, 1000, 2, 50, 1, 1] {
        park.extend_from_slice(&value.to_be_bytes());
    }
    let mut writer = b"DCPBUD01".to_vec();
    writer.extend_from_slice(&4242u64.to_be_bytes());
    writer.extend_from_slice(&1000u64.to_be_bytes());
    let mut control = b"DCPCTL01".to_vec();
    control.extend_from_slice(&4242u64.to_be_bytes());
    control.extend_from_slice(&1u64.to_be_bytes());
    (park, writer, control)
}

#[test]
fn exact_original_body_is_borrowed() {
    let (park, writer, control) = fixture();
    let retained = OriginalTerminalControlPark::parse(&park, &writer, &control, 4242).unwrap();

    assert!(std::ptr::eq(retained.body().as_ptr(), park.as_ptr()));
    assert_eq!(retained.body(), park);
}

#[test]
fn malformed_shape_and_foreign_source_join_refuse() {
    let (park, writer, control) = fixture();
    for offset in [8usize, 16, 24, 48, 56] {
        let mut changed = park.clone();
        changed[offset..offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(OriginalTerminalControlPark::parse(&changed, &writer, &control, 4242).is_err());
    }
    for offset in [8usize, 16] {
        let mut changed = writer.clone();
        changed[offset..offset + 8].copy_from_slice(&42u64.to_be_bytes());
        assert!(OriginalTerminalControlPark::parse(&park, &changed, &control, 4242).is_err());
        let mut changed = control.clone();
        changed[offset..offset + 8].copy_from_slice(&42u64.to_be_bytes());
        assert!(OriginalTerminalControlPark::parse(&park, &writer, &changed, 4242).is_err());
    }
    assert!(OriginalTerminalControlPark::parse(&park, &writer, &control, 42).is_err());
    assert!(OriginalTerminalControlPark::parse(&park[..63], &writer, &control, 4242).is_err());
    let mut trailing = park.clone();
    trailing.push(0);
    assert!(OriginalTerminalControlPark::parse(&trailing, &writer, &control, 4242).is_err());
}

#[test]
fn nonzero_native_u64_inode_is_retained_as_data() {
    let (mut park, writer, control) = fixture();
    park[40..48].copy_from_slice(&u64::MAX.to_be_bytes());
    let retained = OriginalTerminalControlPark::parse(&park, &writer, &control, 4242).unwrap();

    assert_eq!(retained.body(), park);
    park[40..48].copy_from_slice(&0u64.to_be_bytes());
    assert!(OriginalTerminalControlPark::parse(&park, &writer, &control, 4242).is_err());
}
