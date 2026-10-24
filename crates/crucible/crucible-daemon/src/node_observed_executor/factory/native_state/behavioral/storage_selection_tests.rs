//! Checks dispatch selection against the original source-selected Block identity.

use crucible_node_format::Id;

use super::is_selected_storage;
use crate::node_qualification::QualificationError;

#[test]
fn original_block_identity_is_collected_without_a_presentation_alias()
-> Result<(), QualificationError> {
    let original = Id::new("disk-a")?;
    let original_dispatch = Id::new("disk-a")?;
    let stale_literal = Id::new("disk")?;

    assert!(is_selected_storage(&original_dispatch, &original));
    assert!(!is_selected_storage(&stale_literal, &original));
    Ok(())
}

#[test]
fn another_original_owner_cannot_select_the_block_oracle() -> Result<(), QualificationError> {
    let original = Id::new("disk-a")?;

    for name in ["cpu", "clock", "source-a", "disk-b"] {
        assert!(!is_selected_storage(&Id::new(name)?, &original));
    }
    Ok(())
}
