//! Bounds the pinned BTreeMap Clone body's typed returns and control views.
//!
//! Rust 1.98.1 liballoc map.rs226-306 and node.rs190-206,771-775,893,
//! 1754-1757 define this field roster. Bounds include source-field alignment
//! gaps and a word-sized tag for the actual two-variant Rust enums; they do not
//! assert that an arbitrary Rust ABI equals a guessed mirror. The existing
//! source-built compiler pin and checked public geometry anchors are mandatory.
//!
//! These DATA rows remain unselected. Heap tree nodes and child K::clone/V::clone
//! implementations require independent backing and constructor producers. No
//! map is cloned, allocated, mutated or granted authority by this module.

use crate::node_contract::RuntimeError;
use std::{
    alloc::Layout,
    collections::BTreeMap,
    mem::{ManuallyDrop, align_of, size_of},
    ptr::NonNull,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldBound {
    bytes: usize,
    alignment: usize,
}

impl FieldBound {
    fn of<T>() -> Self {
        Self {
            bytes: size_of::<T>(),
            alignment: align_of::<T>(),
        }
    }

    fn record(fields: &[Self]) -> Result<Self, RuntimeError> {
        let mut bytes = 0usize;
        let mut alignment = 1usize;
        for field in fields {
            Layout::from_size_align(field.bytes, field.alignment)
                .map_err(|_| RuntimeError::InvalidReceipt)?;
            bytes = bytes
                .checked_add(field.bytes)
                .ok_or(RuntimeError::ResourceLimit)?;
            alignment = alignment.max(field.alignment);
        }
        // Every possible source-field order has no more than one alignment gap
        // per field plus trailing padding. An extra leading boundary is retained.
        let boundaries = fields
            .len()
            .checked_add(1)
            .ok_or(RuntimeError::ResourceLimit)?;
        bytes = bytes
            .checked_add(
                boundaries
                    .checked_mul(alignment - 1)
                    .ok_or(RuntimeError::ResourceLimit)?,
            )
            .ok_or(RuntimeError::ResourceLimit)?;
        let layout = Layout::from_size_align(bytes, alignment)
            .map_err(|_| RuntimeError::ResourceLimit)?
            .pad_to_align();
        Ok(Self {
            bytes: layout.size(),
            alignment,
        })
    }

    fn two_variant(left: Self, right: Self) -> Result<Self, RuntimeError> {
        let payload = Self {
            bytes: left.bytes.max(right.bytes),
            alignment: left.alignment.max(right.alignment),
        };
        // These exact source enums have two variants and no explicit repr.
        // rustc_abi layout.rs833-908 computes the tagged layout and may widen
        // its 0/1 tag to the first payload field alignment, which is eight
        // for every private enum passed here. lib.rs1307 maps that to I64.
        // layout.rs1076-1093 picks a niche layout only if no larger. These
        // locked rules justify the word bound; Rust has no generic ABI promise.
        Self::record(&[Self::of::<isize>(), payload])
    }
}

/// Defines only the pinned allocator result/branch envelopes as const DATA.
///
/// Slots are fat allocation Result, thin NonNull Result, its residual, and the
/// corresponding ControlFlow branch. AllocError is fieldless. The unchanged
/// FieldBound::two_variant/record proof above gives the same conservative
/// two-field tag/payload algebra. All evaluation occurs in this const item;
/// no runtime FieldBound, Layout query, Try conversion or allocation is run.
pub(in super::super) const GLOBAL_ALLOCATION_LAYOUT_DATA: Option<[usize; 4]> = {
    if size_of::<usize>() != 8
        || align_of::<usize>() != 8
        || size_of::<NonNull<[u8]>>() != 16
        || align_of::<NonNull<[u8]>>() != 8
    {
        None
    } else {
        match (
            allocation_envelope_const(size_of::<NonNull<[u8]>>()),
            allocation_envelope_const(size_of::<NonNull<u8>>()),
            allocation_envelope_const(size_of::<std::convert::Infallible>()),
        ) {
            (Some(fat), Some(thin), Some(residual)) => {
                // The residual bound is conservative, so it also safely bounds
                // that actual field inside ControlFlow's Break variant.
                match allocation_envelope_const(residual) {
                    Some(branch) => Some([fat, thin, residual, branch]),
                    None => None,
                }
            }
            _ => None,
        }
    }
};

// This exact two-field specialization preserves the old FieldBound bodies.
// Its only users are the const initializer above. All selected payloads have
// alignment no greater than the guarded word tag; three gaps include leading,
// between-field and trailing boundaries, then the result is padded to align.
const fn allocation_envelope_const(payload: usize) -> Option<usize> {
    let alignment = align_of::<usize>();
    let padding = match (alignment - 1).checked_mul(3) {
        Some(bytes) => bytes,
        None => return None,
    };
    let bytes = match size_of::<isize>().checked_add(payload) {
        Some(bytes) => bytes,
        None => return None,
    };
    let bytes = match bytes.checked_add(padding) {
        Some(bytes) => bytes,
        None => return None,
    };
    let remainder = bytes % alignment;
    if remainder == 0 {
        Some(bytes)
    } else {
        bytes.checked_add(alignment - remainder)
    }
}

macro_rules! checked_sum {
    ($first:expr $(, $next:expr)* $(,)?) => {{
        let total: usize = $first;
        $(let total = total.checked_add($next).ok_or(RuntimeError::ResourceLimit)?;)*
        total
    }};
}

/// Names field-backed bounds for the private Clone view family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct MapCloneControlLayoutsData {
    /// Bounds any immutable/mutable/owned NodeRef's height, thin pointer and marker.
    pub(in super::super) node_ref_bytes: usize,
    /// Bounds an Edge or KV Handle's NodeRef, index and marker.
    pub(in super::super) handle_bytes: usize,
    /// Bounds ForceResult's Leaf/Internal NodeRef alternatives.
    pub(in super::super) force_result_bytes: usize,
    /// Bounds right_kv's actual KV-handle/edge-handle Result alternatives.
    pub(in super::super) right_kv_result_bytes: usize,
    /// Bounds the owned Root's Some/None envelope without a niche assumption.
    pub(in super::super) optional_root_bytes: usize,
    /// Bounds (Option<Root>, usize) extracted from the owned subtree.
    pub(in super::super) extracted_root_bytes: usize,
    /// Bounds the simultaneously live owned key and value input/local slots.
    pub(in super::super) owned_key_value_bytes: usize,
    /// Bounds the actual (&K, &V) returned by into_kv.
    pub(in super::super) borrowed_key_value_bytes: usize,
    /// Counts the actual public map header with its default Global allocator.
    pub(in super::super) map_bytes: usize,
    /// Counts the actual ManuallyDrop map value used before field extraction.
    pub(in super::super) manually_drop_map_bytes: usize,
    /// Counts a thin borrowed root/view receiver or returned pointer.
    pub(in super::super) pointer_bytes: usize,
    /// Bounds root.as_mut's Option of the actual mutable root loan.
    pub(in super::super) optional_root_loan_bytes: usize,
    /// Bounds root.as_ref's Option of the actual shared root loan.
    pub(in super::super) optional_shared_root_loan_bytes: usize,
    /// Counts a returned/owned-input Box of a Sized leaf node under Global.
    pub(in super::super) leaf_box_bytes: usize,
    /// Counts the corresponding uninitialized leaf Box header.
    pub(in super::super) uninitialized_leaf_box_bytes: usize,
    /// Counts a returned/owned-input Box of a Sized internal node under Global.
    pub(in super::super) internal_box_bytes: usize,
    /// Counts the corresponding uninitialized internal Box header.
    pub(in super::super) uninitialized_internal_box_bytes: usize,
    /// Bounds Box::into_non_null_with_allocator's (thin pointer, Global) return.
    pub(in super::super) allocated_pointer_tuple_bytes: usize,
    /// Counts the actual NonZero<usize> internal-height return/argument.
    pub(in super::super) nonzero_height_bytes: usize,
    /// Counts NonZero::new's actual optional height return.
    pub(in super::super) optional_height_bytes: usize,
    /// Bounds the initialized parent-pointer Some/None write envelope.
    pub(in super::super) optional_parent_pointer_bytes: usize,
    /// Bounds the parent's thin internal pointer and stored u16 index views.
    pub(in super::super) parent_link_bytes: usize,
    /// Counts the actual borrowed mutable V returned from a leaf KV handle.
    pub(in super::super) borrowed_value_bytes: usize,
}

/// Separates owning return/input windows from borrowed/control views.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in super::super) struct MapCloneControlStorageData {
    /// Bounds only the named direct map/subtree/push owning values, not child heaps.
    pub(in super::super) transient_return_bytes: usize,
    /// Bounds the quote controls plus named live Clone control views.
    pub(in super::super) declared_counter_scratch_bytes: usize,
}

fn require_profile(word: Layout, pointer: Layout, map: Layout) -> Result<(), RuntimeError> {
    // This is the existing 64-bit Rust1.98.1 layout profile, not auto-detection
    // of every future liballoc change. Upgrades must re-audit the locked source.
    if word.size() != 8
        || word.align() != 8
        || pointer.size() != 8
        || pointer.align() != 8
        || map.size() != 24
        || map.align() != 8
        || super::value_slot_bytes() != 32
        || size_of::<super::LeafNode<String, serde_json::Value>>() != 632
        || super::map_node_bytes() != 728
    {
        return Err(RuntimeError::UnsupportedFacet);
    }
    Ok(())
}

/// Defines the actual pinned map Clone control layouts without observing a map.
///
/// # Errors
/// Refuses unsupported public profile anchors or checked layout arithmetic.
pub(in super::super) fn map_clone_control_layouts_data<K, V>()
-> Result<MapCloneControlLayoutsData, RuntimeError> {
    require_profile(
        Layout::new::<usize>(),
        Layout::new::<NonNull<super::LeafNode<K, V>>>(),
        Layout::new::<BTreeMap<K, V>>(),
    )?;
    // NodeRef's marker has zero size/alignment1 for all of the exact borrowed,
    // owned and leaf/internal marker forms. LeafNode<K,V> is Sized, so this
    // actual NonNull uses a thin pointer even for over-aligned key/value types.
    let node = FieldBound::record(&[
        FieldBound::of::<usize>(),
        FieldBound::of::<NonNull<super::LeafNode<K, V>>>(),
        FieldBound::of::<std::marker::PhantomData<()>>(),
    ])?;
    let handle = FieldBound::record(&[
        node,
        FieldBound::of::<usize>(),
        FieldBound::of::<std::marker::PhantomData<()>>(),
    ])?;
    let optional_root = FieldBound::two_variant(FieldBound::of::<()>(), node)?;
    let extracted_root = FieldBound::record(&[optional_root, FieldBound::of::<usize>()])?;
    let owned_pair = FieldBound::record(&[FieldBound::of::<K>(), FieldBound::of::<V>()])?;
    let borrowed_pair = FieldBound::record(&[FieldBound::of::<&K>(), FieldBound::of::<&V>()])?;
    let optional_loan =
        FieldBound::two_variant(FieldBound::of::<()>(), FieldBound::of::<&mut ()>())?;
    Ok(MapCloneControlLayoutsData {
        node_ref_bytes: node.bytes,
        handle_bytes: handle.bytes,
        force_result_bytes: FieldBound::two_variant(node, node)?.bytes,
        right_kv_result_bytes: FieldBound::two_variant(handle, handle)?.bytes,
        optional_root_bytes: optional_root.bytes,
        extracted_root_bytes: extracted_root.bytes,
        owned_key_value_bytes: owned_pair.bytes,
        borrowed_key_value_bytes: borrowed_pair.bytes,
        map_bytes: size_of::<BTreeMap<K, V>>(),
        manually_drop_map_bytes: size_of::<ManuallyDrop<BTreeMap<K, V>>>(),
        pointer_bytes: size_of::<&mut ()>(),
        optional_root_loan_bytes: optional_loan.bytes,
        optional_shared_root_loan_bytes: optional_loan.bytes,
        // Only pointer/header geometry is used here. Each referent is Sized;
        // these public Box layouts therefore require no private node ABI guess.
        leaf_box_bytes: size_of::<Box<super::LeafNode<K, V>>>(),
        uninitialized_leaf_box_bytes: size_of::<Box<std::mem::MaybeUninit<super::LeafNode<K, V>>>>(
        ),
        internal_box_bytes: size_of::<Box<super::InternalNode<K, V>>>(),
        uninitialized_internal_box_bytes: size_of::<
            Box<std::mem::MaybeUninit<super::InternalNode<K, V>>>,
        >(),
        // The locked alloc.rs58 default Global is a fieldless ZST. Its Clone
        // and owned argument take zero bytes, while its borrowed views do not.
        allocated_pointer_tuple_bytes: FieldBound::record(&[
            FieldBound::of::<NonNull<super::LeafNode<K, V>>>(),
            FieldBound::of::<()>(),
        ])?
        .bytes,
        nonzero_height_bytes: size_of::<std::num::NonZeroUsize>(),
        optional_height_bytes: size_of::<Option<std::num::NonZeroUsize>>(),
        optional_parent_pointer_bytes: FieldBound::two_variant(
            FieldBound::of::<()>(),
            FieldBound::of::<NonNull<super::InternalNode<K, V>>>(),
        )?
        .bytes,
        parent_link_bytes: FieldBound::record(&[
            FieldBound::of::<NonNull<super::InternalNode<K, V>>>(),
            FieldBound::of::<u16>(),
        ])?
        .bytes,
        borrowed_value_bytes: size_of::<&mut V>(),
    })
}

/// Names fixed views before this DATA supplier's checked arithmetic.
///
/// Recursive compiler activation frames and allocator residency are separate.
pub(in super::super) fn map_clone_control_counter_scratch_data() -> usize {
    size_of::<MapCloneControlLayoutsData>()
        + size_of::<Result<MapCloneControlLayoutsData, RuntimeError>>()
        + size_of::<MapCloneControlStorageData>()
        + size_of::<Result<MapCloneControlStorageData, RuntimeError>>()
        + size_of::<FieldBound>() // record return
        + size_of::<[FieldBound; 7]>() // node, handle, root, tuple, owned/borrowed pairs, loan
        + size_of::<[FieldBound; 3]>() // enum left/right inputs and largest payload local
        + size_of::<&FieldBound>() // record iterator's actual borrowed field
        + size_of::<Result<FieldBound, RuntimeError>>()
        + size_of::<[FieldBound; 3]>()
        + size_of::<[FieldBound; 2]>()
        + size_of::<&[FieldBound]>()
        + size_of::<std::slice::Iter<'static, FieldBound>>()
        + size_of::<Option<&FieldBound>>()
        + size_of::<Layout>() // checked aggregate layout and padded return
        + size_of::<[Layout; 3]>() // profile's word/pointer/map argument windows
        + size_of::<Result<Layout, std::alloc::LayoutError>>()
        + size_of::<Result<Layout, RuntimeError>>()
        + size_of::<Result<(), RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<[usize; 15]>() // two parameters, nodes, nine branch rows, final T/S/total
        + size_of::<[usize; 3]>() // record bytes/alignment/boundaries
        + size_of::<[usize; 2]>() // checked_sum's previous and returned total
        + size_of::<bool>()
}

/// Bounds this direct Clone body's controls using actual initialized entries.
///
/// Every nonempty source node contains at least one initialized entry, so actual
/// map length bounds node occurrences and simultaneous recursive levels. The
/// entry count prices named views, never a missing layout or policy ceiling.
/// The row excludes K::clone/V::clone bodies, tree allocations, generic allocator
/// implementation work, map/node-constructor and parent-link helper bodies, and
/// drop/unwind bodies; callers must compose those. The companion layout result
/// exposes the Box/height/pointer/link forms needed by those helper producers.
/// This unselected producer changes no existing accepted map form or grant.
///
/// # Errors
/// Refuses unsupported pinned geometry, arithmetic overflow or the whole-row bound.
pub(in super::super) fn map_clone_control_storage_data<K: Clone, V: Clone>(
    initialized_len: usize,
    maximum: usize,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    let layouts = map_clone_control_layouts_data::<K, V>()?;
    let nodes = initialized_len;
    // Leaf owns new Root and Some(Root); internal retains the child map while
    // owning ManuallyDrop, extracted root/length and the eventual push root.
    let leaf_returns = checked_sum!(
        layouts.map_bytes,
        layouts.map_bytes,
        layouts.node_ref_bytes,
        layouts.optional_root_bytes
    );
    let internal_returns = checked_sum!(
        layouts.map_bytes,
        layouts.map_bytes,
        layouts.map_bytes,
        layouts.manually_drop_map_bytes,
        layouts.extracted_root_bytes,
        layouts.optional_root_bytes,
        layouts.node_ref_bytes,
        layouts.node_ref_bytes
    );
    let node_returns = leaf_returns.max(internal_returns);
    // Leaf: push arguments, push_with_handle's forwarded arguments, pointer
    // writes. Internal: k/v locals LIVE ACROSS the recursive subtree call,
    // owned push arguments, pointer writes. Child Clone returns are separate.
    let leaf_inputs = checked_sum!(
        layouts.owned_key_value_bytes,
        layouts.owned_key_value_bytes,
        layouts.owned_key_value_bytes
    );
    let internal_inputs = checked_sum!(
        layouts.owned_key_value_bytes,
        layouts.owned_key_value_bytes,
        layouts.owned_key_value_bytes
    );
    let entry_inputs = leaf_inputs.max(internal_inputs);
    // Both alternatives retain original node/force/view, edge, KV/result and
    // returned k/v loans. Internal also retains its descent and push/link edge
    // while recursive child frames exist; all node occurrences bound that sum.
    let leaf_controls = checked_sum!(
        layouts.node_ref_bytes,           // clone_subtree's immutable argument
        layouts.force_result_bytes,       // node.force return
        layouts.node_ref_bytes,           // Leaf pattern value
        layouts.optional_root_loan_bytes, // out_tree.root.as_mut
        layouts.pointer_bytes,            // unwrapped mutable root loan
        layouts.node_ref_bytes,           // root.borrow_mut return
        layouts.force_result_bytes,       // mutable root's force return
        layouts.node_ref_bytes,           // mutable Leaf pattern value
        layouts.handle_bytes,             // in_edge local
        layouts.right_kv_result_bytes,    // right_kv result
        layouts.handle_bytes,             // kv pattern local
        layouts.borrowed_key_value_bytes, // into_kv return
        layouts.handle_bytes,             // right_edge return
        layouts.pointer_bytes,            // outer push's mutable self receiver
        layouts.pointer_bytes,            // nested push_with_handle's mutable self receiver
        layouts.handle_bytes,             // push_with_handle return
        layouts.handle_bytes,             // into_val_mut's owned self argument
        layouts.borrowed_value_bytes,     // into_val_mut's actual &mut V return
        size_of::<*mut V>(),              // coerced push return, discarded by clone_subtree
        size_of::<()>(),                  // sequential pointer-write results
        size_of::<usize>(),               // sequential len/index controls
        size_of::<bool>()                 // loop/refusal predicates
    );
    let internal_controls = checked_sum!(
        layouts.node_ref_bytes,           // clone_subtree's immutable argument
        layouts.force_result_bytes,       // node.force return
        layouts.node_ref_bytes,           // Internal pattern value
        layouts.optional_root_loan_bytes, // out_tree.root.as_mut
        layouts.pointer_bytes,            // out_root mutable loan
        layouts.node_ref_bytes,           // push_internal_level return
        layouts.node_ref_bytes,           // out_node local retained across recursive calls
        layouts.handle_bytes,             // in_edge local
        layouts.right_kv_result_bytes,    // right_kv result
        layouts.handle_bytes,             // kv pattern local
        layouts.borrowed_key_value_bytes, // into_kv return
        layouts.handle_bytes,             // right_edge return
        layouts.node_ref_bytes,           // recursive edge.descend return/argument
        layouts.pointer_bytes,            // internal push receiver
        layouts.handle_bytes,             // corrected-parent-link edge
        size_of::<()>(),                  // push/write/link results
        size_of::<usize>(),               // sequential len/index controls
        size_of::<bool>()                 // loop/refusal predicates
    );
    let node_controls = leaf_controls.max(internal_controls);
    // BTreeMap::clone's outer return is distinct from clone_subtree/new_in's
    // returned map. The default Global allocator is the pinned zero-sized type;
    // its borrowed receiver remains a real pointer control.
    let transient = checked_sum!(
        layouts.map_bytes,
        if nodes == 0 {
            layouts.map_bytes
        } else {
            nodes
                .checked_mul(node_returns)
                .ok_or(RuntimeError::ResourceLimit)?
        },
        initialized_len
            .checked_mul(entry_inputs)
            .ok_or(RuntimeError::ResourceLimit)?
    );
    let scratch = checked_sum!(
        map_clone_control_counter_scratch_data(),
        layouts.pointer_bytes,                   // outer self map receiver
        layouts.pointer_bytes,                   // allocator borrowed receiver
        layouts.optional_shared_root_loan_bytes, // self.root.as_ref return
        layouts.pointer_bytes,                   // unwrapped shared root loan
        layouts.node_ref_bytes,                  // root.reborrow return / clone_subtree argument
        size_of::<bool>(),                       // self.is_empty return
        nodes
            .checked_mul(node_controls)
            .ok_or(RuntimeError::ResourceLimit)?
    );
    let total = transient
        .checked_add(scratch)
        .ok_or(RuntimeError::ResourceLimit)?;
    if total > maximum {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(MapCloneControlStorageData {
        transient_return_bytes: transient,
        declared_counter_scratch_bytes: scratch,
    })
}

#[path = "clone_controls/construction.rs"]
mod construction;
#[path = "clone_controls/initializers.rs"]
mod initializers;
#[path = "clone_controls/sequences.rs"]
mod sequences;

#[cfg(test)]
#[path = "clone_controls/tests.rs"]
mod tests;

/// Composes the pinned map constructor/link helper controls with the direct row.
///
/// Child key/value Clone outputs and backing remain separately composed.
/// Allocator implementation/abort and compiler activation residency are excluded.
///
/// # Errors
/// Refuses unsupported pinned geometry, checked overflow or whole-row exhaustion.
pub(in super::super) fn map_clone_constructor_storage_data<K: Clone, V: Clone>(
    initialized_len: usize,
    maximum: usize,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    construction::map_constructor_storage_data::<K, V>(initialized_len, maximum)
}

/// Names fixed controls before the defining map constructor DATA walk.
pub(in super::super) fn map_clone_constructor_counter_scratch_data() -> usize {
    map_clone_control_counter_scratch_data() + construction::constructor_counter_scratch_data()
}

/// Names the closed sequence constructor DATA controls before a real walk.
pub(in super::super) fn sequence_clone_counter_scratch_data() -> usize {
    map_clone_control_counter_scratch_data() + sequences::counter_scratch_data()
}

/// Defines the pinned Vec/slice/RawVec constructor windows for actual elements.
///
/// The closed caller chooses the audited TrivialClone branch only for u8 and
/// derived Copy FacetKind. Child nontrivial Clone returns/backing are separate.
///
/// # Errors
/// Refuses unsupported geometry, checked overflow or whole-row exhaustion.
pub(in super::super) fn sequence_clone_storage_data<T: 'static>(
    initialized_len: usize,
    trivial_elements: bool,
    maximum: usize,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    sequences::storage_data::<T>(initialized_len, trivial_elements, maximum)
}
