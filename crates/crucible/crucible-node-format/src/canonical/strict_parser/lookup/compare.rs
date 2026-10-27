//! Names the exact identity-Borrow/String/Vec<u8>/byte comparison controls.
//!
//! String's one-field derived Ord calls Vec<u8>::cmp. Its two Deref operations
//! form byte slices; SliceOrd's u8 specialization calls compare_bytes and then
//! compares isize order against zero. This source path allocates and hashes
//! nothing. Length influences work, not backing or the number of live windows.

use super::{
    geometry::{REFERENCE, UNIQUE_U8},
    total,
};
use std::{cmp::Ordering, mem::size_of, ptr::NonNull};

const COMPARE_T: usize = total([
    size_of::<&String>(),  // identity Borrow<String> return
    size_of::<Ordering>(), // String derived Ord return
    size_of::<Ordering>(), // Vec<u8>::cmp return
    size_of::<&[u8]>(),    // left Vec Deref return
    size_of::<&[u8]>(),    // right Vec Deref return
    size_of::<Ordering>(), // [u8]::cmp return
    size_of::<Ordering>(), // SliceOrd::compare return
    size_of::<i32>(),      // compare_bytes intrinsic return
    size_of::<Ordering>(), // isize::cmp return
    size_of::<Ordering>(), // three_way_compare intrinsic return
]);

const COMPARE_S: usize = total([
    size_of::<&String>(),   // Borrow<String>::borrow receiver
    size_of::<&String>(),   // String::cmp self
    size_of::<&String>(),   // String::cmp other
    size_of::<&Vec<u8>>(),  // generated Ord Vec self field loan
    size_of::<&Vec<u8>>(),  // generated Ord Vec other field loan
    size_of::<&Vec<u8>>(),  // Vec::cmp self
    size_of::<&Vec<u8>>(),  // Vec::cmp other
    size_of::<&Vec<u8>>(),  // left Deref receiver
    size_of::<&Vec<u8>>(),  // right Deref receiver
    size_of::<&[u8]>(),     // [u8] Ord self
    size_of::<&[u8]>(),     // [u8] Ord other
    size_of::<&[u8]>(),     // SliceOrd left input
    size_of::<&[u8]>(),     // SliceOrd right input
    size_of::<usize>(),     // left.len result
    size_of::<usize>(),     // right.len result
    size_of::<isize>(),     // left length cast
    size_of::<isize>(),     // right length cast
    size_of::<isize>(),     // diff local
    size_of::<bool>(),      // length comparison
    size_of::<usize>(),     // selected minimum len
    size_of::<*const u8>(), // left slice as_ptr return
    size_of::<*const u8>(), // right slice as_ptr return
    size_of::<*const u8>(), // left cast receiver
    size_of::<*const u8>(), // right cast receiver
    size_of::<*const u8>(), // left cast return / local
    size_of::<*const u8>(), // right cast return / local
    size_of::<*const u8>(), // compare_bytes left argument
    size_of::<*const u8>(), // compare_bytes right argument
    size_of::<usize>(),     // compare_bytes len argument
    size_of::<i32>(),       // intrinsic result before cast
    size_of::<isize>(),     // order cast/local
    size_of::<bool>(),      // order ==0 result
    size_of::<isize>(),     // replacement order=diff operand
    size_of::<&isize>(),    // final Ord self
    size_of::<&isize>(),    // final Ord other/zero loan
    size_of::<isize>(),     // final zero initializer
    size_of::<isize>(),     // three_way_compare self argument
    size_of::<isize>(),     // three_way_compare other argument
]);

// Each Vec dereference calls as_slice -> as_ptr -> RawVec::ptr ->
// RawVecInner::ptr -> non_null -> Unique::cast -> NonNull::cast/as_ptr.
// These are fixed typed controls, not an allocation or raw-buffer owner row.
// The identical left/right chains have independent caller loans and returns.
const BYTE_SLICE_T: usize = total([
    UNIQUE_U8,                // Unique::cast owned self
    size_of::<NonNull<u8>>(), // NonNull::cast owned self
    size_of::<NonNull<u8>>(), // NonNull::as_ptr owned self
    size_of::<*mut u8>(),     // NonNull::as_ptr return inside cast
    size_of::<*mut u8>(),     // cast pointer operand
    size_of::<NonNull<u8>>(), // NonNull::cast return
    UNIQUE_U8,                // Unique initializer
    UNIQUE_U8,                // Unique::cast return
    UNIQUE_U8,                // Unique::as_non_null_ptr owned self
    size_of::<NonNull<u8>>(), // Unique::as_non_null_ptr return
    size_of::<NonNull<u8>>(), // RawVecInner::non_null return
    size_of::<NonNull<u8>>(), // NonNull::as_ptr owned self in ptr
    size_of::<*mut u8>(),     // NonNull::as_ptr return
    size_of::<*mut u8>(),     // RawVecInner::ptr return
    size_of::<*mut u8>(),     // RawVec::ptr return
    size_of::<*const u8>(),   // Vec::as_ptr return
    size_of::<*const [u8]>(), // aggregate_raw_ptr return
    size_of::<&[u8]>(),       // Vec::as_slice return
]);

const BYTE_SLICE_S: usize = total([
    size_of::<&Vec<u8>>(),    // Vec::as_slice receiver
    size_of::<&Vec<u8>>(),    // Vec::as_ptr receiver
    REFERENCE,                // RawVec<u8,Global>::ptr receiver
    REFERENCE,                // RawVecInner<Global>::ptr receiver
    REFERENCE,                // RawVecInner<Global>::non_null receiver
    size_of::<*const u8>(),   // aggregate_raw_ptr data input
    size_of::<usize>(),       // aggregate_raw_ptr len input
    size_of::<*const [u8]>(), // aggregate result to shared slice loan
    size_of::<&[u8]>(),       // as_slice intermediate borrowed result
    size_of::<&[u8]>(),       // byte slice as_ptr receiver
    size_of::<*const [u8]>(), // byte slice pointer cast input
    size_of::<*const u8>(),   // byte slice pointer cast output
]);

pub(super) const TRANSIENT: usize = total([COMPARE_T, BYTE_SLICE_T, BYTE_SLICE_T]);
pub(super) const SCRATCH: usize = total([COMPARE_S, BYTE_SLICE_S, BYTE_SLICE_S]);
