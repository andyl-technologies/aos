//! Borrow and failure-position invariants for lifecycle prefix reads.

use aos_sandbox_protocol::domain_ledger::lifecycle_model::LifecycleModelError;

use super::*;

#[test]
fn prefix_reads_retain_original_borrows_and_commit_only_successful_ranges() {
    let original = [1, 2, 3, 4, 5, 6];
    for offset in 0..=original.len() {
        for length in (0..=original.len() + 1).chain([usize::MAX]) {
            let before = &original[offset..];
            let mut remaining = before;

            let result = take_slice(&mut remaining, length);

            if length <= before.len() {
                let value = result.unwrap();
                assert_eq!(value, &before[..length]);
                assert!(std::ptr::eq(value.as_ptr(), before.as_ptr()));
                assert_eq!(remaining, &before[length..]);
                assert!(std::ptr::eq(remaining.as_ptr(), before[length..].as_ptr()));
            } else {
                assert_eq!(result, Err(LifecycleModelError::CorruptEncoding));
                assert_eq!(remaining, before);
                assert!(std::ptr::eq(remaining.as_ptr(), before.as_ptr()));
            }
        }
    }
}

#[test]
fn fixed_width_reads_refuse_short_input_without_losing_the_retry_tail() {
    let original = [1, 2, 3, 4, 5, 6];
    for length in 0..4 {
        let before = &original[..length];
        let mut remaining = before;

        assert_eq!(
            take::<4>(&mut remaining),
            Err(LifecycleModelError::CorruptEncoding)
        );
        assert_eq!(remaining, before);
        assert_eq!(take::<0>(&mut remaining), Ok([]));
        assert!(std::ptr::eq(remaining.as_ptr(), before.as_ptr()));
    }
    let mut remaining = original.as_slice();

    assert_eq!(take::<4>(&mut remaining), Ok([1, 2, 3, 4]));
    assert_eq!(
        take::<4>(&mut remaining),
        Err(LifecycleModelError::CorruptEncoding)
    );
    assert_eq!(take::<2>(&mut remaining), Ok([5, 6]));
    assert!(remaining.is_empty());
}

#[test]
fn count_conversion_requires_exact_width_without_imposing_a_semantic_cap() {
    assert_eq!(
        usize_from_u32(&[0; 3]),
        Err(LifecycleModelError::CorruptEncoding)
    );
    assert_eq!(
        usize_from_u32(&[0; 5]),
        Err(LifecycleModelError::CorruptEncoding)
    );
    assert_eq!(usize_from_u32(&0_u32.to_be_bytes()), Ok(0));
    assert_eq!(
        usize_from_u32(&u32::MAX.to_be_bytes()),
        usize::try_from(u32::MAX).map_err(|_| LifecycleModelError::CorruptEncoding)
    );
}
