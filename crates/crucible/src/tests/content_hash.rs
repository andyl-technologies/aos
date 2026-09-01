//! Canonical content-hash construction regressions.

use super::*;

#[test]
fn canonical_material_bytes_preserve_string_identity() {
    let material = "target:6:node-a;";
    assert_eq!(
        ContentHash::from_canonical_material("crucible.test.bytes", material),
        ContentHash::from_canonical_material_bytes("crucible.test.bytes", material.as_bytes())
    );
}
