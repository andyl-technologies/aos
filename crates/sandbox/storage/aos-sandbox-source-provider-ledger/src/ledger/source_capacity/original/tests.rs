//! UNRUN aggregate borrowed-challenge bounds, without graph or writer authority.

use super::*;

#[test]
fn challenge_borrowed_width_sum_and_count_are_checked_without_retention() {
    let key = [1; 40];
    let value = [2; 296];
    let row = OriginalSourceChallengeDataV5 {
        acquisition: ObjectDigest::from_bytes([3; 32]), key: &key, value: &value,
    };
    assert!(bound_challenges(&[row]).is_ok());
    assert!(validate_original_source_challenge_data_bounds_v5(&[row]).is_ok());
    let many = vec![row; crate::limits::MAXIMUM_LEDGER_RECORDS + 1];
    assert!(bound_challenges(&many).is_err());
    assert_eq!(value, [2; 296]);
}
