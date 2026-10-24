//! Lists the transitive pinned node windows reached by BTreeMap::clone.
//!
//! Helpers have no recursive call into themselves. Summing their windows once
//! covers one clone_subtree level, even when loops visit multiple entries.
//! Recursive clone_subtree levels and nested Value clones compose separately.
//! The caller supplies source-field bounds for private NodeRef and Handle.

use super::{ProviderError, WORD, record, total};
use std::mem::{MaybeUninit, size_of};

// These actual array types also bind the quote-control supplier to its rosters.
type DataTransientFields = [usize; 75];
type DataScratchFields = [usize; 37];

/// Names the actual quote arrays and their checked field/result accumulators.
pub(super) fn quote_counter_scratch_data() -> usize {
    size_of::<DataTransientFields>()
        + size_of::<DataScratchFields>()
        + size_of::<[usize; 2]>() * 2
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<usize>() * 9
        + size_of::<Result<usize, ProviderError>>() * 3
        + size_of::<Result<[usize; 2], ProviderError>>()
}

/// Counts reachable node construction, navigation, append and parent-link work.
///
/// # Errors
/// Refuses checked field-bound or source-window accumulation overflow.
pub(super) fn data<K, V>(
    node: usize,
    handle: usize,
    forced_node: usize,
) -> Result<[usize; 2], ProviderError> {
    let pointer = size_of::<std::ptr::NonNull<()>>();
    let boxed_node = record(&[pointer, 0])?; // Box<private node,Global>: Unique, allocator
    let edge_result = record(&[WORD, handle])?;
    let optional_parent = record(&[WORD, pointer])?;
    let transient_fields: DataTransientFields = [
        // LeafNode::new / InternalNode::new allocate uninitialized nodes and
        // initialize in place. Only their actual Box headers are transient.
        boxed_node, // new_uninit_in return / local
        boxed_node, // assume_init owned input
        boxed_node, // assume_init return
        boxed_node, // concrete node constructor return
        // NodeRef::new_leaf -> from_new_leaf -> Root::new.
        boxed_node, // from_new_leaf owned argument
        pointer,    // into_non_null_with_allocator result
        node,       // from_new_leaf initializer
        node,       // from_new_leaf return
        node,       // new_leaf return
        node,       // forget_type owned argument
        node,       // forget_type initializer
        node,       // forget_type return / Root::new return
        // mem::take_mut -> replace reads the old Root, calls the zero-capture
        // Global-allocator closure, and writes its new Root. PanicGuard is ZST.
        node, // ptr::read(v) / value
        node, // change(value) owned argument
        node, // change return / new_value
        node, // ptr::write owned operand
        // NodeRef::new_internal / from_new_internal / push_internal_level.
        node,       // new_internal child argument
        boxed_node, // new internal boxed local
        boxed_node, // from_new_internal owned argument
        pointer,    // into_non_null_with_allocator result
        node,       // from_new_internal initializer / this
        node,       // from_new_internal return
        node,       // new_internal return
        node,       // forget_type argument
        node,       // forget_type initializer
        node,       // forget_type return
        node,       // push_internal_level initializer
        node,       // push_internal_level return
        // Immutable reborrow, mutable reborrow and borrow_mut have concrete
        // NodeRef initializer/return windows, with thin borrowed receivers.
        node, // reborrow initializer
        node, // reborrow return
        node, // reborrow_mut initializer
        node, // reborrow_mut return
        node, // borrow_mut initializer
        node, // borrow_mut return
        // force transfers its NodeRef into exactly one of the two variants.
        node,        // force owned input
        node,        // variant owned operand
        forced_node, // variant initializer
        forced_node, // force return
        // first_edge / new_edge / new_kv construct the actual Handle records.
        node,   // first_edge owned input
        node,   // new_edge owned input
        handle, // new_edge initializer
        handle, // new_edge return
        handle, // first_edge return
        node,   // new_kv owned input
        handle, // new_kv initializer
        handle, // new_kv return
        // right_kv and right_edge move existing node views; no key or Value
        // clone occurs in these navigation helpers.
        handle,      // right_kv owned input
        handle,      // new_kv result / Ok owned operand
        edge_result, // Ok/Err initializer
        edge_result, // right_kv return
        handle,      // right_edge owned input
        node,        // new_edge owned argument
        handle,      // right_edge new handle
        handle,      // right_edge return
        // descend and into_kv/into_val_mut consume their actual Handle. Their
        // private LeafNode references remain thin borrowed views below.
        handle,  // descend owned input
        pointer, // assume_init_read child pointer
        node,    // descend initializer
        node,    // descend return
        handle,  // into_kv owned input
        node,    // into_leaf owned input
        handle,  // into_val_mut owned input
        node,    // into_leaf_mut owned input
        // Leaf push -> push_with_handle -> new_kv -> into_val_mut. Internal
        // push additionally consumes the owned child Root and corrects links.
        size_of::<K>(),  // leaf push key
        size_of::<V>(),  // leaf push value
        size_of::<K>(),  // push_with_handle key
        size_of::<V>(),  // push_with_handle value
        node,            // push_with_handle NodeRef initializer
        handle,          // push_with_handle return
        size_of::<K>(),  // internal push key
        size_of::<V>(),  // internal push value
        node,            // internal push child edge
        handle,          // internal push edge-handle initializer
        handle,          // correct_parent_link owned input
        node,            // corrected child view
        optional_parent, // set_parent_link Some(parent) initializer
    ];
    let transient = total(&transient_fields)?;
    let scratch_fields: DataScratchFields = [
        size_of::<*mut ()>(),                  // uninitialized node pointer
        size_of::<*mut ()>(),                  // node initialization receiver
        size_of::<&mut ()>(),                  // private root receiver
        size_of::<&()>(),                      // private NodeRef receiver
        size_of::<&mut ()>(),                  // private NodeRef mutable receiver
        size_of::<&mut ()>(),                  // mem::replace target
        size_of::<usize>(),                    // new_internal height
        size_of::<std::num::NonZero<usize>>(), // checked new height
        size_of::<Option<std::num::NonZero<usize>>>(),
        size_of::<&mut MaybeUninit<std::ptr::NonNull<()>>>(), // first child edge
        size_of::<&mut u16>(),                                // leaf/internal len_mut
        size_of::<usize>(),                                   // push index
        size_of::<&mut [MaybeUninit<K>]>(),                   // key_area_mut slice
        size_of::<&mut MaybeUninit<K>>(),                     // key_area_mut element
        size_of::<&mut [MaybeUninit<V>]>(),                   // val_area_mut slice
        size_of::<&mut MaybeUninit<V>>(),                     // val_area_mut element
        size_of::<&mut [MaybeUninit<std::ptr::NonNull<()>>]>(), // edge area
        size_of::<&mut MaybeUninit<std::ptr::NonNull<()>>>(),
        size_of::<*mut ()>(),           // as_leaf_ptr
        size_of::<&()>(),               // into_leaf result
        size_of::<&mut ()>(),           // into_leaf_mut result
        size_of::<&[MaybeUninit<K>]>(), // into_kv keys
        size_of::<&MaybeUninit<K>>(),
        size_of::<&K>(),
        size_of::<&[MaybeUninit<V>]>(), // into_kv values
        size_of::<&MaybeUninit<V>>(),
        size_of::<&V>(),
        size_of::<&mut MaybeUninit<V>>(), // into_val_mut slot
        size_of::<&mut V>(),
        size_of::<usize>(), // correct_all_childrens_parent_links len
        size_of::<std::ops::RangeInclusive<usize>>(), // child edge range
        size_of::<Option<usize>>(), // child edge iterator result
        size_of::<usize>(), // current child index
        size_of::<*mut ()>(), // correct_parent_link parent pointer
        size_of::<usize>(), // correct_parent_link parent index
        size_of::<*mut ()>(), // set_parent_link leaf pointer
        size_of::<&mut ()>(), // set_parent_link child receiver
    ];
    let scratch = total(&scratch_fields)?;
    Ok([transient, scratch])
}
