//! Bounds destruction of the SDK validator's temporary borrowed version set.
//!
//! The pinned Rust 1.98.1 BTreeMap Drop consumes IntoIter, whose dying_next and
//! LazyLeafRange deallocation use loops rather than recursive destruction.
//! The actual key is &String and the internal value is zero-field SetValZST:
//! neither drops an owned child. Owning String/Id trees are outside this row.
//! Private records follow map.rs, navigate.rs and node.rs field rosters.

use super::{ProviderError, WORD, node_helpers, record, supported, total};
use std::mem::{MaybeUninit, size_of};

type TransientFields = [usize; 25];
type ScratchFields = [usize; 23];

/// Names actual quote arrays and checked private-record accumulators.
pub(in super::super) fn quote_counter_scratch_data() -> usize {
    size_of::<TransientFields>()
        + size_of::<ScratchFields>()
        + node_helpers::quote_counter_scratch_data()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[usize; 2]>() * 5
        + size_of::<usize>() * 12
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<[usize; 2], ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

/// Bounds complete normal destruction of a BTreeSet of borrowed String keys.
///
/// Nodes are deallocated in place. No key or node backing is copied. A concrete
/// panic-free borrowed-key drop excludes user destructor callbacks; this row
/// is not a bound for arbitrary K::drop or panic-reporting machinery.
///
/// # Errors
/// Refuses an unsupported pinned layout or checked accumulation overflow.
pub(in super::super) fn borrowed_data() -> Result<[usize; 2], ProviderError> {
    supported()?;
    let node = record(&[WORD, size_of::<std::ptr::NonNull<()>>(), 0])?;
    let handle = record(&[node, WORD, 0])?;
    let forced_node = record(&[WORD, node])?;
    let optional_node = record(&[WORD, node])?;
    let optional_handle = record(&[WORD, handle])?;
    let edge_result = record(&[WORD, handle])?;
    // LazyLeafHandle is Root(NodeRef) or Edge(Handle); LazyLeafRange has two
    // optional handles. IntoIter is that range, length and Global allocator.
    let lazy = record(&[WORD, node.max(handle)])?;
    let optional_lazy = record(&[WORD, lazy])?;
    let range = record(&[optional_lazy, optional_lazy])?;
    let iterator = record(&[range, WORD, 0])?;
    let next = record(&[WORD, handle])?;
    let pair = record(&[handle, handle])?;
    let optional_pair = record(&[WORD, pair])?;
    let helpers = node_helpers::data::<&'static String, ()>(node, handle, forced_node)?;
    let transient_fields: TransientFields = [
        size_of::<std::collections::BTreeSet<&String>>(), // original validator local
        size_of::<std::collections::BTreeSet<&String>>(), // map ptr::read / ManuallyDrop
        optional_node,                                    // original root.take
        node,                                             // into_dying receiver
        node,                                             // into_dying return
        node,                                             // full_range first root
        node,                                             // full_range second root
        lazy,                                             // Root initializer
        optional_lazy,                                    // Some(Root) initializer
        range,                                            // full_range initializer
        range,                                            // full_range return
        iterator,                                         // IntoIter initializer
        iterator,        // into_iter return / Drop receiver operand
        handle,          // dying_next output operand
        next,            // dying_next return
        handle,          // drop loop kv binding
        pair,            // deallocating_next return pair
        optional_pair,   // deallocating_next return
        handle,          // next_leaf_edge receiver
        handle,          // next_leaf_edge return
        edge_result,     // right_kv / ascend result
        node,            // deallocate_and_ascend receiver
        optional_handle, // deallocate_and_ascend return
        handle,          // forgotten-node-type initializer / return
        helpers[0],      // transitive force, descend and edge-navigation moves
    ];
    let scratch_fields: ScratchFields = [
        size_of::<&mut ()>(),                   // BTreeMap / IntoIter / range receiver
        size_of::<&mut ()>(),                   // DropGuard's complete one-field roster
        size_of::<&mut ()>(),                   // mem::replace handle target
        handle,                                 // deallocating loop edge
        optional_handle,                        // returned parent / init_front handle
        next,                                   // drop loop condition
        node,                                   // descending front root
        forced_node,                            // first_leaf_edge force result
        handle,                                 // initialized front edge
        size_of::<usize>(),                     // current tree height
        size_of::<std::ptr::NonNull<()>>(),     // node to deallocate
        size_of::<std::alloc::Layout>(),        // actual leaf/internal allocation layout
        size_of::<u16>(),                       // parent edge index
        size_of::<&mut ()>(),                   // private dying leaf reference
        size_of::<&mut MaybeUninit<&String>>(), // key slot
        size_of::<&mut MaybeUninit<()>>(),      // audited empty value slot
        size_of::<&mut MaybeUninit<()>>(),      // Dropper's complete one-field roster
        size_of::<usize>(),                     // remaining IntoIter length
        size_of::<bool>(),                      // root/leaf branch
        size_of::<&()>(),                       // zero-sized Global allocator borrow
        size_of::<*mut ()>(),                   // allocator deallocation pointer
        size_of::<Option<std::ptr::NonNull<()>>>(), // parent pointer
        helpers[1],
    ];
    Ok([total(&transient_fields)?, total(&scratch_fields)?])
}
