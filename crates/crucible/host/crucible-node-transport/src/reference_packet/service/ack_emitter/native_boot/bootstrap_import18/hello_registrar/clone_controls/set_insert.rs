//! Bounds the pinned incremental BTreeSet insertion used by initial SDK admission.
//!
//! Rust 1.98.1 alloc/src/collections/btree/{set.rs,set_val.rs,map.rs,
//! map/entry.rs,search.rs,borrow.rs,node.rs} defines this closed container path.
//! Search and separator propagation are loops, including insert_recursing;
//! no population multiplier or invented recursive call stack is needed.
//! Private records below follow complete field rosters with alignment gaps.
//! They are bounds, not ABI mirrors or constructed library-private objects.
//!
//! Heap nodes, caller-owned keys and concrete key comparison/drop/clone work
//! are separate caller terms. In particular this supplier never assumes that
//! an arbitrary K::cmp is allocation-free.

use super::{ALIGNMENT, ProviderError, WORD, node_helpers, record, refused, supported, total};
use std::mem::{MaybeUninit, align_of, size_of};

type TransientFields = [usize; 51];
type ScratchFields = [usize; 51];

/// Names the supplier's actual arrays and checked private-record controls.
pub(in super::super) fn quote_counter_scratch_data() -> usize {
    size_of::<TransientFields>()
        + size_of::<ScratchFields>()
        + node_helpers::quote_counter_scratch_data()
        + size_of::<[usize; 5]>()
        + size_of::<[usize; 3]>() * 3
        + size_of::<[usize; 2]>() * 4
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<usize>() * 13
        + size_of::<Result<usize, ProviderError>>() * 5
        + size_of::<Result<[usize; 2], ProviderError>>() * 2
        + size_of::<Result<(), ProviderError>>()
}

/// Bounds one incremental set insertion, including occupied and root-split paths.
///
/// All insertion nodes remain in the resulting set: there is no auxiliary
/// heap workspace or node-sized stack copy. Global and the actual private
/// SetValZST are zero-field types. Using () in helper field sizes names that
/// audited zero-width value; it does not substitute a BTreeMap<K, ()> ABI.
///
/// # Errors
/// Refuses unsupported pinned layout/alignment or checked accumulation overflow.
pub(in super::super) fn data<K: 'static>() -> Result<[usize; 2], ProviderError> {
    supported()?;
    if align_of::<K>() > ALIGNMENT {
        return Err(refused());
    }

    let node = record(&[WORD, size_of::<std::ptr::NonNull<()>>(), 0])?;
    let handle = record(&[node, WORD, 0])?;
    let forced_node = record(&[WORD, node])?;
    let edge_result = record(&[WORD, handle])?;
    // DormantMutRef is NonNull<T> plus PhantomData<&mut T>.
    let dormant = record(&[size_of::<std::ptr::NonNull<()>>(), 0])?;
    let optional_handle = record(&[WORD, handle])?;
    // VacantEntry: key, optional handle, dormant map, Global, PhantomData.
    let vacant = record(&[size_of::<K>(), optional_handle, dormant, 0, 0])?;
    // OccupiedEntry: handle, dormant map, Global, PhantomData.
    let occupied = record(&[handle, dormant, 0, 0])?;
    let entry = record(&[WORD, vacant.max(occupied)])?;
    // SplitResult: left NodeRef, (K, SetValZST), right owned NodeRef.
    let split = record(&[node, size_of::<K>(), node])?;
    let optional_split = record(&[WORD, split])?;
    let helpers = node_helpers::data::<K, ()>(node, handle, forced_node)?;

    let transient_fields: TransientFields = [
        size_of::<K>(),                                  // BTreeSet::insert owned key
        size_of::<K>(),                                  // BTreeMap::insert owned key
        size_of::<K>(),                                  // BTreeMap::entry owned key
        vacant,                                          // empty-map VacantEntry initializer
        vacant,                                          // populated-map VacantEntry initializer
        occupied,                                        // occupied-map OccupiedEntry initializer
        entry,                                           // entry return / insert match operand
        vacant,                                          // vacant match binding
        occupied,                                        // occupied match binding
        vacant,                                          // VacantEntry::insert receiver
        vacant,                                          // insert_entry receiver
        occupied,                                        // insert_entry return
        occupied,                                        // into_mut receiver
        dormant,                                         // DormantMutRef::new initializer
        size_of::<(&mut (), *mut ())>(), // new returns map borrow and dormant pointer
        node,                            // search_tree receiver
        edge_result,                     // search_node result
        edge_result,                     // search_tree result
        handle,                          // search_node match binding
        node,                            // force match leaf or internal node
        handle,                          // leaf edge returned to entry
        size_of::<K>(),                  // insert_recursing owned key
        size_of::<K>(),                  // leaf insert owned key
        size_of::<K>(),                  // internal insert owned separator
        size_of::<K>(),                  // insert_fit owned key
        split,                           // leaf/internal SplitResult initializer
        split,                           // split return
        optional_split,                  // insert optional split return
        size_of::<(usize, usize)>(),     // splitpoint index and LeftOrRight payload; tag below
        WORD,                            // LeftOrRight discriminant
        split,                           // insert_recursing split local
        split,                           // forget_node_type owned argument
        split,                           // forget_node_type return
        edge_result,                     // ascend result
        handle,                          // parent match binding
        node,                            // root match binding
        split,                           // root split callback argument
        split,                           // split_leaf_data receiver path
        size_of::<K>(),                  // split separator assume_init_read / returned key
        size_of::<(K, ())>(),            // split_leaf_data return; audited empty set value
        node,                            // fresh split right Root
        node,                            // split left reborrow
        handle,                          // leaf/internal split insertion edge
        handle,                          // insert_fit return
        handle,                          // dormant inserted-value handle
        handle,                          // awaken receiver and returned handle
        size_of::<K>(),                  // slice_insert owned key
        size_of::<MaybeUninit<K>>(),     // slice_insert key write operand
        size_of::<std::ptr::NonNull<()>>(), // slice_insert owned child edge
        size_of::<MaybeUninit<std::ptr::NonNull<()>>>(), // slice_insert edge write operand
        helpers[0], // transitive node initialization, push, links and navigation
    ];
    let scratch_fields: ScratchFields = [
        size_of::<&mut std::collections::BTreeSet<K>>(), // set receiver
        size_of::<&mut ()>(),                            // private map receiver
        size_of::<&K>(),                                 // key comparison operand
        size_of::<&K>(),                                 // borrowed search key
        size_of::<&mut K>(),                             // replacement key/value slot upper bound
        size_of::<&mut ()>(),                            // dormant reborrow result
        dormant,                                         // dormant_map local
        size_of::<&mut ()>(),                            // root borrow
        node,                                            // borrowed root
        node,                                            // search_tree loop node
        handle,                                          // search_node edge
        forced_node,                                     // search_tree force result
        edge_result,                                     // search result
        size_of::<&[K]>(),                               // search_node keys
        size_of::<std::slice::Iter<'static, K>>(),       // find_key_index iteration
        size_of::<std::iter::Enumerate<std::slice::Iter<'static, K>>>(), // enumerated search keys
        size_of::<Option<(usize, &K)>>(),                // search next result
        size_of::<std::cmp::Ordering>(),                 // key comparison result
        size_of::<usize>(),                              // search start index
        size_of::<usize>(),                              // search current index
        size_of::<&mut ()>(),                            // split_root closure captured dormant map
        size_of::<&()>(),   // split_root closure captured Global allocator
        size_of::<usize>(), // split insertion index
        size_of::<usize>(), // splitpoint result index
        size_of::<usize>(), // old node length
        size_of::<usize>(), // new node length
        size_of::<std::num::NonZero<usize>>(), // new internal height
        size_of::<&mut [MaybeUninit<K>]>(), // split_leaf_data source keys
        size_of::<&mut [MaybeUninit<K>]>(), // split_leaf_data destination keys
        size_of::<&mut [MaybeUninit<()>]>(), // empty set value source slice
        size_of::<&mut [MaybeUninit<()>]>(), // empty set value destination slice
        size_of::<&mut [MaybeUninit<std::ptr::NonNull<()>>]>(), // source child edges
        size_of::<&mut [MaybeUninit<std::ptr::NonNull<()>>]>(), // destination child edges
        size_of::<*const K>(), // move_to_slice key source
        size_of::<*mut K>(), // move_to_slice key destination
        size_of::<usize>(), // move_to_slice length
        size_of::<*const ()>(), // empty value move source
        size_of::<*mut ()>(), // empty value move destination
        size_of::<usize>(), // empty value move length
        size_of::<*const std::ptr::NonNull<()>>(), // child edge move source
        size_of::<*mut std::ptr::NonNull<()>>(), // child edge move destination
        size_of::<usize>(), // child edge move length
        size_of::<&mut [MaybeUninit<K>]>(), // slice_insert key slice
        size_of::<usize>(), // slice_insert index
        size_of::<usize>(), // slice_insert length
        size_of::<*mut MaybeUninit<K>>(), // slice_insert key destination
        size_of::<&mut MaybeUninit<K>>(), // slice_insert write receiver
        size_of::<&mut u16>(), // updated node length
        size_of::<Option<std::ptr::NonNull<()>>>(), // ascend parent
        size_of::<u16>(),   // ascend parent index
        helpers[1],         // transitive node helper controls
    ];
    Ok([total(&transient_fields)?, total(&scratch_fields)?])
}
