//! Bounds logical controls of the pinned fresh String, Vec and tree clones.
//!
//! Rust 1.98.1 alloc/src/{string.rs,slice.rs,vec/mod.rs} and
//! alloc/src/collections/btree/{map.rs,node.rs} define these source windows.
//! Private record bounds follow their complete field rosters and alignment gaps;
//! they are not ABI mirrors, constructed private values or physical stack claims.
//! Allocating backing, caller partial owners and validation are separate terms.
//!
//! These rows cover fresh cloning only. Their quote controls and the enclosing
//! validation, shared allocations and owner transition must join the complete
//! constructor row before it may admit native construction.

use crate::ProviderError;
use std::mem::{MaybeUninit, align_of, size_of};

// These actual array types also bind the quote-control supplier to its rosters.
type StringDataTransientFields = [usize; 5];
type StringDataScratchFields = [usize; 8];
type VectorDataTransientFields = [usize; 3];
type VectorDataScratchFields = [usize; 10];
type TreeDataRootFields = [usize; 2];
type TreeDataPerLevelTransientFields = [usize; 21];
type TreeDataPerLevelScratchFields = [usize; 23];

#[path = "clone_controls/node_helpers.rs"]
mod node_helpers;

#[path = "clone_controls/set_insert.rs"]
mod set_insert;
pub(super) use set_insert::{
    data as set_insertion_data,
    quote_counter_scratch_data as set_insertion_quote_counter_scratch_data,
};

#[path = "clone_controls/set_drop.rs"]
mod set_drop;
pub(super) use set_drop::{
    borrowed_data as borrowed_set_drop_data,
    quote_counter_scratch_data as set_drop_quote_counter_scratch_data,
};

#[path = "clone_controls/typed.rs"]
mod typed;
pub(super) use typed::{CloneControls, combine};

const WORD: usize = size_of::<usize>();
const ALIGNMENT: usize = 8;

/// Names this supplier's actual source arrays and checked geometry controls.
pub(super) fn quote_counter_scratch_data() -> usize {
    size_of::<StringDataTransientFields>()
        + size_of::<StringDataScratchFields>()
        + size_of::<VectorDataTransientFields>()
        + size_of::<VectorDataScratchFields>()
        + size_of::<TreeDataRootFields>()
        + size_of::<TreeDataPerLevelTransientFields>()
        + size_of::<TreeDataPerLevelScratchFields>()
        + node_helpers::quote_counter_scratch_data()
        + size_of::<[usize; 3]>() * 2
        + size_of::<[usize; 2]>() * 4
        + size_of::<Option<[usize; 3]>>()
        + size_of::<std::slice::Iter<'static, usize>>()
        + size_of::<usize>() * 14
        + size_of::<Result<usize, ProviderError>>() * 4
        + size_of::<Result<[usize; 2], ProviderError>>() * 2
        + size_of::<Result<(), ProviderError>>()
}

/// Prices fresh String::clone and its concrete trivial-byte Vec clone branch.
///
/// # Errors
/// Refuses an unsupported pinned layout or checked accumulation overflow.
pub(in super::super) fn string_data() -> Result<[usize; 2], ProviderError> {
    supported()?;
    let transient_fields: StringDataTransientFields = [
        size_of::<Vec<u8>>(), // to_vec_in fresh Vec local
        size_of::<Vec<u8>>(), // to_vec_in return
        size_of::<Vec<u8>>(), // Vec::clone return
        size_of::<String>(),  // String { vec } initializer
        size_of::<String>(),  // String::clone return
    ];
    let transient = total(&transient_fields)?;
    let scratch_fields: StringDataScratchFields = [
        size_of::<&String>(),   // String::clone receiver
        size_of::<&Vec<u8>>(),  // Vec::clone receiver
        size_of::<&[u8]>(),     // dereferenced original Vec slice
        size_of::<&[u8]>(),     // to_vec_in / trivial to_vec receiver
        size_of::<usize>(),     // original slice len
        size_of::<*const u8>(), // copy source
        size_of::<*mut u8>(),   // fresh Vec destination
        size_of::<usize>(),     // copy length
    ];
    let scratch = total(&scratch_fields)?;
    Ok([transient, scratch])
}

/// Prices the nontrivial element branch of fresh Vec::clone.
///
/// The caller adds the actual element's clone window. Its backing is retained
/// separately; only one element clone is active in this loop at a time.
///
/// # Errors
/// Refuses an unsupported pinned layout or checked accumulation overflow.
pub(super) fn vector_data<T: 'static>() -> Result<[usize; 2], ProviderError> {
    supported()?;
    let transient_fields: VectorDataTransientFields = [
        size_of::<Vec<T>>(), // to_vec_in fresh Vec local
        size_of::<Vec<T>>(), // to_vec_in return
        size_of::<Vec<T>>(), // Vec::clone return
    ];
    let transient = total(&transient_fields)?;
    // Actual slice::to_vec_in DropGuard fields: &mut Vec<T>, num_init:usize.
    // Its alignment is word alignment regardless of the element's alignment.
    let guard = record(&[size_of::<&mut Vec<T>>(), WORD])?;
    let scratch_fields: VectorDataScratchFields = [
        size_of::<&Vec<T>>(),
        size_of::<&[T]>(),
        size_of::<&[T]>(),
        guard,
        size_of::<&mut [MaybeUninit<T>]>(), // spare_capacity_mut slots
        size_of::<std::iter::Take<std::iter::Enumerate<std::slice::Iter<'static, T>>>>(),
        size_of::<Option<(usize, &T)>>(), // next iteration / match
        size_of::<usize>(),               // enumerated initialized index
        size_of::<&T>(),
        size_of::<&mut MaybeUninit<T>>(),
    ];
    let scratch = total(&scratch_fields)?;
    Ok([transient, scratch])
}

/// Prices one complete root-to-leaf window of the actual BTreeMap clone.
///
/// A tree of `entries` items has at most bit_length(entries) occupied levels:
/// every internal node has at least two children and every occupied node has
/// an item. Empty maps take the direct BTreeMap::new_in branch. Nested JSON
/// clone windows and the actual K/V clone windows remain separate caller terms.
///
/// # Errors
/// Refuses an unsupported pinned field alignment or checked arithmetic overflow.
pub(super) fn tree_data<K, V>(entries: usize) -> Result<[usize; 2], ProviderError> {
    supported()?;
    if align_of::<K>() > ALIGNMENT || align_of::<V>() > ALIGNMENT {
        return Err(refused());
    }
    let map = size_of::<std::collections::BTreeMap<K, V>>();
    // Actual NodeRef: height:usize, node:NonNull<LeafNode>, PhantomData.
    let node = record(&[WORD, size_of::<std::ptr::NonNull<()>>(), 0])?;
    // Actual Handle: node:NodeRef, idx:usize, PhantomData.
    let handle = record(&[node, WORD, 0])?;
    // ForceResult<Leaf,Internal> and Result<KVHandle,EdgeHandle> each carry
    // exactly one corresponding payload and the pinned small discriminant.
    let forced_node = record(&[WORD, node])?;
    let edge_result = record(&[WORD, handle])?;
    let optional_root = record(&[WORD, node])?;
    let root_fields: TreeDataRootFields = [
        map, // clone / new_in result
        map, // final clone return
    ];
    let root = total(&root_fields)?;
    if entries == 0 {
        return Ok([root, size_of::<&std::collections::BTreeMap<K, V>>()]);
    }

    let levels = usize::try_from(usize::BITS - entries.leading_zeros()).map_err(|_| refused())?;
    let helpers = node_helpers::data::<K, V>(node, handle, forced_node)?;
    let per_level_transient_fields: TreeDataPerLevelTransientFields = [
        helpers[0],
        node,           // clone_subtree owned input
        forced_node,    // clone_subtree force match operand
        node,           // leaf/internal match binding
        node,           // out_node binding
        handle,         // in_edge initializer
        edge_result,    // right_kv match operand
        handle,         // kv match binding
        map,            // clone_subtree out_tree
        map,            // recursive clone_subtree return
        map,            // internal subtree local
        map,            // ManuallyDrop::new(subtree) owned operand
        map,            // ManuallyDrop initializer
        optional_root,  // ptr::read(subtree.root) / subroot
        optional_root,  // optional-root return
        node,           // unwrapped subtree root owned operand
        size_of::<K>(), // cloned separator retained across subtree recursion
        size_of::<V>(),
        size_of::<K>(),     // push owned key operand
        size_of::<V>(),     // push owned value operand
        size_of::<usize>(), // subtree length
    ];
    let per_level_transient = total(&per_level_transient_fields)?;
    let per_level_scratch_fields: TreeDataPerLevelScratchFields = [
        helpers[1],
        node,                 // clone_subtree node input
        forced_node,          // node.force result
        node,                 // actual leaf/internal match binding
        size_of::<&mut ()>(), // out_tree.root.as_mut() root borrow
        node,                 // out_root.borrow_mut() / push_internal_level return
        forced_node,          // borrowed root force result
        node,                 // out_node binding
        handle,               // in_edge
        edge_result,          // in_edge.right_kv result
        handle,               // kv match binding
        size_of::<&K>(),      // into_kv key
        size_of::<&V>(),      // into_kv value
        handle,               // next right edge
        node,                 // descend return / recursive owned argument
        size_of::<&mut ()>(), // node len_mut
        size_of::<usize>(),   // push slot index
        size_of::<*mut K>(),  // key_area_mut
        size_of::<*mut V>(),  // val_area_mut
        size_of::<*mut ()>(), // edge_area_mut
        handle,               // pushed-edge / pushed-value handle
        size_of::<*mut ()>(), // new_uninit_in boxed node pointer
        size_of::<*mut ()>(), // initialized boxed node pointer
    ];
    let per_level_scratch = total(&per_level_scratch_fields)?;
    Ok([
        root.checked_add(
            per_level_transient
                .checked_mul(levels)
                .ok_or_else(refused)?,
        )
        .ok_or_else(refused)?,
        per_level_scratch.checked_mul(levels).ok_or_else(refused)?,
    ])
}

fn supported() -> Result<(), ProviderError> {
    if cfg!(all(target_arch = "x86_64", target_pointer_width = "64"))
        && WORD == ALIGNMENT
        && align_of::<usize>() == ALIGNMENT
        && size_of::<std::ptr::NonNull<()>>() == WORD
        && crucible_node_format::canonical::STRICT_JSON_KEY_LOOKUP_STORAGE_DATA.is_some()
    {
        Ok(())
    } else {
        Err(refused())
    }
}

fn record(fields: &[usize]) -> Result<usize, ProviderError> {
    let gaps = fields
        .len()
        .checked_add(1)
        .and_then(|n| n.checked_mul(ALIGNMENT - 1))
        .ok_or_else(refused)?;
    total(fields)?
        .checked_add(gaps)
        .and_then(|n| n.checked_add(ALIGNMENT - 1))
        .map(|n| n & !(ALIGNMENT - 1))
        .ok_or_else(refused)
}

fn total(fields: &[usize]) -> Result<usize, ProviderError> {
    fields.iter().try_fold(0usize, |sum, field| {
        sum.checked_add(*field).ok_or_else(refused)
    })
}

fn refused() -> ProviderError {
    ProviderError::ResourceExhausted("original Hello fresh clone controls")
}
