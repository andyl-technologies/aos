//! Names common node, allocation, selector and initialized-move controls.
//!
//! All private views use field-backed bounds from layouts, not a public mirror.
//! Each group follows the pinned source bodies named beside it. Groups are
//! summed conservatively; no allocator implementation or compiler frame is
//! inferred from these typed argument/local/return declarations.

use super::{layouts::*, total};
use serde_json::Value;
use std::{
    alloc::Layout,
    mem::{ManuallyDrop, MaybeUninit, size_of},
    ptr::NonNull,
};

// node.rs73-97,113-128; boxed.rs574-619,1199,1669-1680,1731-1734.
// Leaf and internal constructors call the same Box path sequentially. Their
// allocation can overlap only with outer Split/Root owners listed by insertion.
pub(super) const BOX_T: usize = total([
    POINTER,                            // Box::from_raw_in return
    BOX_RESULT,                         // try_new_uninit_in return
    POINTER,                            // new_uninit_in Ok pattern / return
    POINTER,                            // node new uninitialized Box local
    POINTER,                            // assume_init owned input
    POINTER,                            // assume_init initialized Box return
    POINTER,                            // node new return
    POINTER,                            // from_new_* owned Box argument
    POINTER,                            // into_non_null_with_allocator owned argument
    POINTER,                            // into_raw_with_allocator owned argument
    POINTER,                            // ManuallyDrop::new owned Box argument
    POINTER,                            // MaybeDangling::new argument
    POINTER,                            // transparent MaybeDangling return
    size_of::<ManuallyDrop<Box<()>>>(), // ManuallyDrop return
    size_of::<ManuallyDrop<Box<()>>>(), // into_raw local
    ALLOCATION_TUPLE,                   // raw pointer + Global return
    ALLOCATION_TUPLE,                   // NonNull + Global return
    ALLOCATION_RESULT,                  // Global::allocate return
    ALLOCATION_RESULT,                  // alloc_impl return
    ALLOCATION_RESULT,                  // alloc_impl_runtime return
]);

pub(super) const BOX_S: usize = total([
    size_of::<Layout>(),              // new_uninit layout
    size_of::<Layout>(),              // try_new_uninit layout
    size_of::<NonNull<[u8]>>(),       // Ok allocation pattern
    POINTER,                          // cast pointer return
    POINTER,                          // Box::from_raw pointer argument
    UNIQUE,                           // actual Unique pointer constructor return
    POINTER,                          // raw local in into_raw
    POINTER,                          // ManuallyDrop::deref_mut receiver
    POINTER,                          // MaybeDangling::as_mut receiver
    POINTER,                          // MaybeDangling::as_mut return
    POINTER,                          // outer deref_mut return
    POINTER,                          // ManuallyDrop::deref receiver
    POINTER,                          // MaybeDangling::as_ref receiver
    POINTER,                          // MaybeDangling::as_ref return
    POINTER,                          // outer deref return
    POINTER,                          // borrowed Global allocator field
    POINTER,                          // NonNull pattern local
    POINTER,                          // NonNull::new_unchecked argument
    POINTER,                          // NonNull::new_unchecked return
    size_of::<bool>(),                // T::IS_ZST
    POINTER,                          // Box::deref_mut receiver during node init
    POINTER,                          // returned MaybeUninit node loan
    POINTER,                          // as_mut_ptr receiver
    POINTER,                          // as_mut_ptr return
    POINTER,                          // LeafNode::init pointer argument
    POINTER,                          // raw parent field pointer
    size_of::<Option<NonNull<u8>>>(), // parent None write
    POINTER,                          // raw len field pointer
    size_of::<u16>(),                 // zero len write
    POINTER,                          // allocate borrowed Global
    size_of::<Layout>(),              // allocate input
    POINTER,                          // alloc_impl borrowed Global
    size_of::<Layout>(),              // alloc_impl input
    size_of::<bool>(),                // alloc_impl zeroed=false
    size_of::<(Layout, bool)>(),      // const_eval_select runtime argument tuple
    size_of::<Layout>(),              // alloc_impl_runtime input
    size_of::<bool>(),                // runtime zeroed argument
    WORD,                             // matched size
    size_of::<Layout>(),              // alloc(Layout) input
    WORD,                             // __rust_alloc size
    WORD,                             // __rust_alloc alignment
    POINTER,                          // allocator ABI raw result
    POINTER,                          // raw_ptr local
    size_of::<Option<NonNull<u8>>>(), // NonNull::new result
    THIN_ALLOCATION_RESULT,           // alloc_impl_runtime .ok_or(AllocError) return
    THIN_ALLOCATION_RESULT,           // thin Result::branch owned self
    THIN_ALLOCATION_TRY,              // thin Try::branch ControlFlow return
    POINTER,                          // thin Continue success-pattern NonNull<u8>
    ALLOC_ERROR_RESIDUAL,             // thin Break residual pattern
    ALLOC_ERROR_RESIDUAL,             // Global-return FromResidual owned input
    ALLOCATION_RESULT,                // same-AllocError converted Global Result return
    ALLOCATION_RESULT,                // Box try_new_uninit_in fat Result::branch owned self
    FAT_ALLOCATION_TRY,               // fat Try::branch ControlFlow return
    size_of::<NonNull<[u8]>>(),       // fat Continue success-pattern pointer
    ALLOC_ERROR_RESIDUAL,             // fat Break residual pattern
    ALLOC_ERROR_RESIDUAL,             // Box-return FromResidual owned input
    BOX_RESULT,                       // same-AllocError converted Box Result return
    size_of::<()>(),                  // fieldless AllocError pattern, identity From input/return
    POINTER,                          // ptr local
    size_of::<NonNull<[u8]>>(),       // cast_slice return
    size_of::<bool>(),                // nonzero / allocation success predicates
]);

// node.rs224-263: root/leaf/internal owned returns and the initialized child
// input stay separate from the Box movement path above.
pub(super) const CONSTRUCTOR_T: usize = total([
    BOX_T, NODE, // from_new_leaf return
    NODE, // new_leaf return
    NODE, // forget_type owned input
    NODE, // forget_type return
    NODE, // new_internal child argument
    NODE, // from_new_internal return
    NODE, // new_internal return
    NODE, // from_new_internal this local
    NODE, // this.borrow_mut returned view
    NODE, // final this return
]);

pub(super) const CONSTRUCTOR_S: usize = total([
    BOX_S,
    POINTER,                                      // from_new_leaf destructured pointer local
    WORD,                                         // initialized height=0
    POINTER,                                      // new_internal Box mutable edge receiver
    POINTER,                                      // initialized child edge pointer
    size_of::<Option<std::num::NonZeroUsize>>(),  // NonZero::new return
    size_of::<std::num::NonZeroUsize>(),          // unwrapped height
    size_of::<std::num::NonZeroUsize>(),          // from_new_internal argument
    POINTER,                                      // internal Box's destructured node local
    WORD,                                         // height.into return
    POINTER,                                      // correct_all_childrens receiver
    WORD,                                         // len local
    size_of::<std::ops::RangeInclusive<usize>>(), // 0..=len argument
    size_of::<std::ops::RangeInclusive<usize>>(), // owned loop iterator
    size_of::<Option<usize>>(),                   // loop next return
    WORD,                                         // loop i
    size_of::<std::ops::Range<usize>>(),          // insert_fit's alternate parent range
    size_of::<std::ops::Range<usize>>(),          // owned alternate iterator
    POINTER,                                      // correct_childrens receiver
    POINTER,                                      // set_parent_link mutable receiver
    POINTER,                                      // owned parent argument
    WORD,                                         // parent_idx argument
    POINTER,                                      // leaf local / field pointer
    size_of::<Option<NonNull<u8>>>(),             // initialized Some parent
    size_of::<u16>(),                             // initialized parent_idx cast
    size_of::<&mut MaybeUninit<u16>>(),           // index write receiver
    size_of::<&mut u16>(),                        // index write return
    move_write_s::<u16>(),
    move_write_t::<u16>(),
]);

// Insertion-only selectors: node.rs270-358,387-443,638-655,
// 813-877,1102-1142,1663-1702. Retirement has its own reached subset.
pub(super) const SELECT_T: usize = total([
    NODE, // NodeRef::reborrow returned shared node view
    NODE, // reborrow_mut return
    NODE, // Root::borrow_mut return
    NODE,
    NODE, // cast_to_leaf input / return
    NODE,
    NODE, // forget_type input / return
    NODE,
    NODE,       // force owned input / variant payload
    FORCE_NODE, // force returned enum
    HANDLE,
    HANDLE,       // Handle::force owned input / payload
    FORCE_HANDLE, // Handle::force returned enum
    NODE,
    HANDLE, // new_edge owned input / return
    NODE,
    HANDLE, // new_kv owned input / return
    HANDLE, // Handle::dormant return
    NODE,   // NodeRef::dormant return
    HANDLE, // Handle::awaken owned self
    NODE,
    NODE,   // NodeRef::awaken input / return
    HANDLE, // Handle::awaken return
    HANDLE,
    HANDLE, // forget_node_type owned self / return
    NODE,   // NodeRef::into_leaf_mut owned input
    HANDLE, // into_val_mut owned handle
    HANDLE,
    NODE, // descend owned input / returned child
    NODE, // correct_parent_link mutable child local
]);

pub(super) const SELECT_S: usize = total([
    POINTER,
    POINTER, // len receiver / as_leaf_ptr argument
    POINTER,
    POINTER, // raw leaf return / local
    size_of::<u16>(),
    WORD, // scalar len / returned usize
    POINTER,
    POINTER, // as_internal_ptr receiver / returned raw ptr
    POINTER,
    POINTER, // as_internal_mut receiver / returned loan
    POINTER,
    POINTER,                                      // as_leaf_mut receiver / returned loan
    POINTER,                                      // NodeRef::reborrow receiver
    POINTER,                                      // NodeRef::reborrow_mut receiver
    POINTER,                                      // Root::borrow_mut receiver
    WORD,                                         // force height
    WORD,                                         // new_edge index
    WORD,                                         // new_kv index
    WORD,                                         // descend index / height
    POINTER,                                      // descend parent_ptr local
    size_of::<&[MaybeUninit<NonNull<u8>>; 12]>(), // edge array loan
    size_of::<&MaybeUninit<NonNull<u8>>>(),       // selected edge
    POINTER,
    POINTER,
    POINTER, // assume_init_read/as_ptr/ptr::read inputs
    POINTER,
    POINTER,                                    // read pointer / assume_init_read return
    POINTER,                                    // Handle::dormant receiver
    POINTER,                                    // NodeRef::dormant receiver
    POINTER,                                    // into_leaf_mut as_leaf_ptr receiver
    POINTER,                                    // into_leaf_mut returned leaf
    size_of::<&mut [MaybeUninit<Value>; 11]>(), // into_val_mut array loan
    size_of::<&mut MaybeUninit<Value>>(),       // selected val
    size_of::<&mut Value>(),                    // assume_init_mut return
    size_of::<&mut Value>(),                    // actual into_val_mut return
    POINTER,
    POINTER,           // parent link raw ptr / NonNull result
    WORD,              // parent index local
    size_of::<bool>(), // selector/validity predicates
]);

// node.rs478-544: scalar and range accessors, including their nested raw/slice
// views. Calls for key, value and edge are sequential, so each typed family has
// one helper roster. Their owning callers remain in insertion's direct rows.
pub(super) const AREA_S: usize = total([
    area_s::<String, 11>(),
    area_s::<Value, 11>(),
    area_s::<NonNull<u8>, 12>(),
]);

const fn area_s<T, const N: usize>() -> usize {
    total([
        POINTER,                               // key/val/edge_area_mut receiver
        WORD,                                  // scalar index operand
        size_of::<std::ops::RangeTo<usize>>(), // insert range
        size_of::<std::ops::Range<usize>>(),   // split range
        POINTER,                               // as_leaf/internal_mut argument
        POINTER,                               // as_leaf/internal_mut return
        size_of::<&mut [MaybeUninit<T>; N]>(), // actual 11-key/value or 12-edge array loan
        size_of::<&mut [MaybeUninit<T>]>(),    // as_mut_slice return
        size_of::<&mut [MaybeUninit<T>]>(),    // get_unchecked_mut receiver
        size_of::<*mut [MaybeUninit<T>]>(),    // raw slice index input
        POINTER,                               // selected raw element address
        size_of::<&mut MaybeUninit<T>>(),      // scalar accessor return
        size_of::<&mut [MaybeUninit<T>]>(),    // range accessor return
        POINTER,                               // len_mut receiver
        POINTER,                               // len_mut nested as_leaf_mut return
        size_of::<&mut u16>(),                 // len_mut return
    ])
}

// The exact initializer chain reused by all three insertion element families:
// MaybeUninit::write -> MaybeUninit::new -> ManuallyDrop::new -> MaybeDangling::new.
const fn move_write_t<T>() -> usize {
    total([
        size_of::<T>(),               // write owned argument
        size_of::<T>(),               // MaybeUninit::new owned argument
        size_of::<T>(),               // ManuallyDrop::new owned argument
        size_of::<T>(),               // MaybeDangling::new owned argument
        size_of::<T>(),               // repr(transparent) MaybeDangling return
        size_of::<ManuallyDrop<T>>(), // ManuallyDrop return
        size_of::<MaybeUninit<T>>(),  // MaybeUninit::new return
    ])
}

const fn move_write_s<T>() -> usize {
    total([
        size_of::<&mut MaybeUninit<T>>(), // write receiver
        size_of::<&mut MaybeUninit<T>>(), // assume_init_mut receiver
        size_of::<&mut MaybeUninit<T>>(), // as_mut_ptr receiver
        size_of::<*mut T>(),              // as_mut_ptr return
        size_of::<&mut T>(),              // assume_init_mut return
        size_of::<&mut T>(),              // write return
    ])
}

// node.rs1822-1831,1874-1880: each actual String, Value and edge-pointer path.
pub(super) const SLICE_T: usize = total([
    move_write_t::<String>(),
    move_write_t::<Value>(),
    move_write_t::<NonNull<u8>>(),
    KEY,
    VALUE,
    POINTER, // slice_insert owned argument, outside nested write
]);
pub(super) const SLICE_S: usize = total([
    slice_s::<String>(),
    slice_s::<Value>(),
    slice_s::<NonNull<u8>>(),
    move_write_s::<String>(),
    move_write_s::<Value>(),
    move_write_s::<NonNull<u8>>(),
]);
const fn slice_s<T>() -> usize {
    total([
        size_of::<&mut [MaybeUninit<T>]>(), // slice_insert argument
        WORD,                               // idx
        WORD,                               // len local
        size_of::<*mut MaybeUninit<T>>(),   // as_mut_ptr return / slice_ptr
        size_of::<*mut MaybeUninit<T>>(),   // copy source
        size_of::<*mut MaybeUninit<T>>(),   // copy destination
        WORD,                               // shifted count
        size_of::<&mut [MaybeUninit<T>]>(), // move_to_slice source argument
        size_of::<&mut [MaybeUninit<T>]>(), // destination argument
        size_of::<*const MaybeUninit<T>>(), // source as_ptr
        size_of::<*mut MaybeUninit<T>>(),   // destination as_mut_ptr
        WORD,                               // copy_nonoverlapping count
        size_of::<bool>(),                  // source/destination length comparison
    ])
}

// node.rs329-358: ascend retains self while mapping its parent, constructing
// from_internal and converting the actual Option<Handle> into Result.
pub(super) const ASCEND_T: usize = total([
    NODE,            // ascend owned self
    NODE,            // from_internal return
    HANDLE,          // map closure return
    OPTIONAL_HANDLE, // parent Option map result
    NODE,            // ok_or owned Err argument
    ASCEND_RESULT,   // ascend return
]);
pub(super) const ASCEND_S: usize = total([
    POINTER,                           // self as_leaf_ptr loan
    POINTER,                           // leaf_ptr local
    size_of::<Option<NonNull<u8>>>(),  // parent field copy
    size_of::<Option<&NonNull<u8>>>(), // as_ref return
    size_of::<&NonNull<u8>>(),         // map closure parent argument
    POINTER,                           // parent copied value/from_internal input
    WORD,                              // from_internal height argument
    WORD,                              // parent idx read
    size_of::<MaybeUninit<u16>>(),     // assume_init owned input
    size_of::<u16>(),                  // index read return
    size_of::<bool>(),                 // mapped branch
]);

// liballoc Global allocator runtime dispatch; backend implementation residency
// is excluded, but every concrete deallocate API/dispatch operand is explicit.
pub(super) const DEALLOC_S: usize = total([
    POINTER,                            // Global::deallocate receiver
    POINTER,                            // deallocate ptr argument
    size_of::<Layout>(),                // deallocate layout argument
    POINTER,                            // deallocate_impl receiver
    POINTER,                            // dispatch ptr input
    size_of::<Layout>(),                // dispatch layout input
    size_of::<(NonNull<u8>, Layout)>(), // const_eval_select runtime tuple
    POINTER,                            // runtime ptr argument
    size_of::<Layout>(),                // runtime layout input
    WORD,                               // checked layout size
    POINTER,                            // dealloc_nonnull pointer input
    size_of::<Layout>(),                // dealloc_nonnull layout input
    WORD,
    WORD,              // allocator ABI size/alignment
    size_of::<bool>(), // nonzero layout predicate
]);
