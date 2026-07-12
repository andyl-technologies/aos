//! WHNF tag-test precursor for thunk forcing.
//!
//! The active runtime value ABI is the safe 16-byte tagged pair from
//! `ratchet-value`: every non-thunk tag is already weak head normal form
//! (WHNF), and only [`ValueTag::Thunk`](crate::value::ValueTag::Thunk) must
//! enter the thunk protocol. This module gives the parallel thunk work a small
//! evaluator-facing boundary for that fact. It is deliberately not the future
//! low-bit pointer-tag fast path: a serial thunk that has already cached a
//! forced result is still represented as a `Thunk` value here, so it still
//! falls through to the thunk cell.

use super::heap::{EvalHeap, EvalHeapError, EvalThunk};
use crate::value::Value;

/// A force-entry decision made from the active value tag.
#[derive(Clone, Copy, Debug)]
pub enum WhnfTagFastPath {
    /// The value is not tagged as a thunk and can be returned by inspection.
    AlreadyWhnf(Value),
    /// The value is tagged as a thunk and must use the thunk protocol.
    RequiresThunkProtocol(Value),
}

impl WhnfTagFastPath {
    /// Returns the value that was classified.
    pub const fn value(self) -> Value {
        match self {
            Self::AlreadyWhnf(value) | Self::RequiresThunkProtocol(value) => value,
        }
    }

    /// Returns whether the value can bypass the thunk protocol.
    pub const fn is_already_whnf(self) -> bool {
        matches!(self, Self::AlreadyWhnf(_))
    }
}

/// A force-entry decision with the slow-path thunk handle checked.
#[derive(Clone, Copy, Debug)]
pub enum CheckedWhnfTagFastPath<'heap> {
    /// The value is not tagged as a thunk and can be returned by inspection.
    AlreadyWhnf(Value),
    /// The value is tagged as a thunk and was resolved to this evaluator heap.
    RequiresThunkProtocol {
        /// The thunk-tagged value that missed the fast path.
        value: Value,
        /// The checked suspended-work record for the thunk protocol.
        thunk: &'heap EvalThunk,
    },
}

impl CheckedWhnfTagFastPath<'_> {
    /// Returns the value that was classified.
    pub const fn value(self) -> Value {
        match self {
            Self::AlreadyWhnf(value) | Self::RequiresThunkProtocol { value, .. } => value,
        }
    }

    /// Returns whether the value can bypass the thunk protocol.
    pub const fn is_already_whnf(self) -> bool {
        matches!(self, Self::AlreadyWhnf(_))
    }
}

/// Classifies a value using only its active ABI tag.
///
/// This is the current semantic WHNF fast path: non-thunks return without a
/// heap lookup, atomic load, or CAS; thunk-tagged values fall through to the
/// caller's thunk protocol. The future pointer-tagged ABI can refine this by
/// recognizing already-forced thunk pointers through the low-bit `FORCED`
/// shortcut, but this function intentionally does not read thunk state.
pub const fn classify_whnf_tag_fast_path(value: Value) -> WhnfTagFastPath {
    if value.is_whnf() {
        WhnfTagFastPath::AlreadyWhnf(value)
    } else {
        WhnfTagFastPath::RequiresThunkProtocol(value)
    }
}

/// Classifies a value and resolves thunk misses through the evaluator heap.
///
/// Non-thunk WHNF values return by tag inspection only. Thunk-tagged values are
/// checked with [`EvalHeap::get_thunk`] so the caller receives the typed thunk
/// record that the CAS or serial thunk protocol will operate on.
///
/// # Errors
///
/// Returns [`EvalHeapError::Value`] if a thunk-tagged value carries an invalid
/// heap pointer payload. Returns [`EvalHeapError::UnknownPointer`] if the thunk
/// pointer does not belong to `heap`, or [`EvalHeapError::RecordTypeMismatch`]
/// if it belongs to `heap` but references a non-thunk record.
pub fn checked_whnf_tag_fast_path(
    heap: &EvalHeap,
    value: Value,
) -> Result<CheckedWhnfTagFastPath<'_>, EvalHeapError> {
    match classify_whnf_tag_fast_path(value) {
        WhnfTagFastPath::AlreadyWhnf(value) => Ok(CheckedWhnfTagFastPath::AlreadyWhnf(value)),
        WhnfTagFastPath::RequiresThunkProtocol(value) => {
            let thunk = heap.get_thunk(value)?;
            Ok(CheckedWhnfTagFastPath::RequiresThunkProtocol { value, thunk })
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::NonNull;

    use super::*;
    use crate::compile::IrId;
    use crate::eval::thunk::{ForceClaim, ThunkState};
    use crate::string::NixString;
    use crate::value::{HeapObject, ValueTag};

    fn dangling_heap_ptr() -> NonNull<HeapObject> {
        NonNull::<HeapObject>::dangling()
    }

    // Baseline test builds float values via `Value::float`; the variant boxes
    // floats (needs a heap). Its WHNF classification is exercised by the parity
    // battery (cutover plan section 7).
    #[cfg(not(feature = "candidate_c_value"))]
    #[test]
    fn whnf_tags_return_by_inspection_without_heap_lookup() {
        let heap = EvalHeap::new();
        let ptr = dangling_heap_ptr();
        let values = [
            Value::int(1),
            Value::float(1.25),
            Value::bool(false),
            Value::null(),
            Value::string(ptr).expect("aligned string pointer"),
            Value::path(ptr).expect("aligned path pointer"),
            Value::list(ptr).expect("aligned list pointer"),
            Value::attrs(ptr).expect("aligned attrs pointer"),
            Value::lambda(ptr).expect("aligned lambda pointer"),
            Value::primop(ptr).expect("aligned primop pointer"),
            Value::external(ptr).expect("aligned external pointer"),
        ];

        for value in values {
            let decision = classify_whnf_tag_fast_path(value);
            match decision {
                WhnfTagFastPath::AlreadyWhnf(classified) => assert!(classified.raw_eq(value)),
                WhnfTagFastPath::RequiresThunkProtocol(_) => {
                    panic!("WHNF tag should not enter thunk protocol")
                }
            }
            assert!(decision.is_already_whnf());
            assert!(decision.value().raw_eq(value));

            let checked =
                checked_whnf_tag_fast_path(&heap, value).expect("WHNF value does not touch heap");
            assert!(checked.is_already_whnf());
            assert!(checked.value().raw_eq(value));
        }
    }

    #[test]
    fn thunk_tags_miss_the_fast_path() {
        let value = Value::thunk(dangling_heap_ptr()).expect("aligned thunk pointer");

        let decision = classify_whnf_tag_fast_path(value);

        match decision {
            WhnfTagFastPath::RequiresThunkProtocol(classified) => assert!(classified.raw_eq(value)),
            WhnfTagFastPath::AlreadyWhnf(_) => panic!("thunk tag should miss the fast path"),
        }
        assert!(!decision.is_already_whnf());
        assert!(decision.value().raw_eq(value));
    }

    #[test]
    fn checked_thunk_miss_returns_heap_thunk_handle() {
        let mut heap = EvalHeap::new();
        let value = heap
            .alloc_thunk(EvalThunk::new(IrId::new(7)))
            .expect("thunk allocates");

        let checked = checked_whnf_tag_fast_path(&heap, value).expect("thunk resolves");

        match checked {
            CheckedWhnfTagFastPath::RequiresThunkProtocol {
                value: classified,
                thunk,
            } => {
                assert!(classified.raw_eq(value));
                assert_eq!(thunk.body(), Some(IrId::new(7)));
            }
            CheckedWhnfTagFastPath::AlreadyWhnf(_) => {
                panic!("thunk must enter the thunk protocol")
            }
        }
    }

    #[test]
    fn checked_thunk_miss_rejects_foreign_heap_pointer() {
        let ptr = dangling_heap_ptr();
        let value = Value::thunk(ptr).expect("aligned thunk pointer");
        let heap = EvalHeap::new();

        let error = checked_whnf_tag_fast_path(&heap, value).expect_err("foreign thunk rejects");

        assert_eq!(
            error,
            EvalHeapError::UnknownPointer {
                tag: ValueTag::Thunk,
                address: ptr.as_ptr() as usize,
            }
        );
    }

    #[test]
    fn checked_thunk_miss_rejects_heap_record_type_mismatch() {
        let mut heap = EvalHeap::new();
        let string = heap
            .alloc_string(NixString::from_bytes(b"not-a-thunk".to_vec()))
            .expect("string allocates");
        let ptr = string.as_string_ptr().expect("string pointer");
        let retagged = Value::thunk(ptr).expect("retagged pointer stays aligned");

        let error =
            checked_whnf_tag_fast_path(&heap, retagged).expect_err("retagged string rejects");

        assert_eq!(
            error,
            EvalHeapError::RecordTypeMismatch {
                expected: ValueTag::Thunk,
                actual: ValueTag::String,
                address: ptr.as_ptr() as usize,
            }
        );
    }

    #[test]
    fn forced_serial_thunk_still_misses_current_tag_fast_path() {
        let mut heap = EvalHeap::new();
        let value = heap
            .alloc_thunk(EvalThunk::new(IrId::new(9)))
            .expect("thunk allocates");
        let thunk = heap.get_thunk(value).expect("thunk resolves");
        let ForceClaim::Claimed(guard) = thunk.cell().begin_force().expect("claim succeeds") else {
            panic!("fresh thunk should be claimable");
        };
        guard
            .finish(Value::int(42))
            .expect("forced result publishes");
        assert_eq!(thunk.cell().state(), Ok(ThunkState::Forced));

        let checked = checked_whnf_tag_fast_path(&heap, value).expect("forced thunk resolves");

        match checked {
            CheckedWhnfTagFastPath::RequiresThunkProtocol {
                value: classified, ..
            } => assert!(classified.raw_eq(value)),
            CheckedWhnfTagFastPath::AlreadyWhnf(_) => {
                panic!("current ABI does not encode the forced-thunk shortcut")
            }
        }
    }

    #[test]
    fn ordinary_heap_values_do_not_need_to_belong_to_this_heap_for_tag_return() {
        let mut foreign_heap = EvalHeap::new();
        let value = foreign_heap
            .alloc_string(NixString::from_bytes(b"foreign".to_vec()))
            .expect("string allocates");
        let local_heap = EvalHeap::new();

        let checked =
            checked_whnf_tag_fast_path(&local_heap, value).expect("non-thunks skip heap lookup");

        assert!(matches!(checked, CheckedWhnfTagFastPath::AlreadyWhnf(_)));
        assert!(checked.value().raw_eq(value));
    }
}
