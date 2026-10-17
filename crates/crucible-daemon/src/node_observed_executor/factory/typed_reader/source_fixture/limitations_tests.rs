//! Checks complete original public limitation bodies without native source authority.

use super::*;
use crucible_node_contract::{Bytes, canonical};

#[test]
fn all_three_original_bodies_must_be_present_exact_and_unique() -> Result<(), ProviderError> {
    let bytes = b"complete planned limitations";
    let reference = canonical::content_ref(bytes, "application/octet-stream")?;
    let exact = [InstalledContent {
        reference: reference.clone(),
        bytes: Bytes::new(bytes.to_vec()),
    }];
    let empty = [];
    let corrupt = [InstalledContent {
        reference: reference.clone(),
        bytes: Bytes::new(b"changed planned limitations".to_vec()),
    }];
    let duplicate = [exact[0].clone(), exact[0].clone()];

    let complete = bodies([exact.as_slice(); 3].into_iter(), &reference)?;
    assert_eq!(complete, bytes);
    assert!(
        bodies(
            [exact.as_slice(), exact.as_slice(), empty.as_slice()].into_iter(),
            &reference
        )
        .is_err()
    );
    assert!(
        bodies(
            [exact.as_slice(), corrupt.as_slice(), exact.as_slice()].into_iter(),
            &reference
        )
        .is_err()
    );
    assert!(
        bodies(
            [duplicate.as_slice(), exact.as_slice(), exact.as_slice()].into_iter(),
            &reference
        )
        .is_err()
    );
    assert!(bodies([exact.as_slice(); 2].into_iter(), &reference).is_err());
    Ok(())
}
