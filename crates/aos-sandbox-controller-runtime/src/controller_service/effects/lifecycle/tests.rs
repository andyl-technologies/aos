//! Original regression fixture for the fixed-width nonzero lifecycle identity.

#![allow(
    clippy::unwrap_used,
    reason = "Fixture construction and regression assertions intentionally panic."
)]

use super::*;

#[test]
fn lifecycle_digest_id_uses_a_nonzero_prefix() {
    let mut digest = [0; 32];
    digest[31] = 7;
    let mut expected = [0; 16];
    expected[15] = 1;
    assert_eq!(nonzero_lifecycle_id_from_digest(digest), expected);

    digest[0] = 9;
    let mut expected = [0; 16];
    expected[0] = 9;
    assert_eq!(nonzero_lifecycle_id_from_digest(digest), expected);
}
