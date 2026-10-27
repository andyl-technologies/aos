//! Composes the locked map/node construction and parent-link typed windows.
//!
//! Each term names an actual function argument, local or return from the pinned
//! liballoc bodies. The default Global allocator is zero sized. Allocator API
//! inputs/results are named; allocator implementation residency, OOM abort,
//! unwinding and compiler activation frames remain outside these logical rows.

use super::*;

fn box_construction_data(
    initialized_box: usize,
    uninitialized_box: usize,
    allocation_tuple: usize,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    let boxed_result = FieldBound::two_variant(
        FieldBound {
            bytes: uninitialized_box,
            alignment: align_of::<usize>(),
        },
        FieldBound::of::<()>(),
    )?;
    let allocation_result =
        FieldBound::two_variant(FieldBound::of::<NonNull<[u8]>>(), FieldBound::of::<()>())?;
    let unique_pointer = FieldBound::record(&[
        FieldBound::of::<NonNull<u8>>(),
        FieldBound::of::<std::marker::PhantomData<u8>>(),
    ])?;
    // boxed.rs574-619,1199,1669-1680,1731-1734: the source-owned header
    // moves and return envelopes remain distinct declared constructor roles.
    let transient = checked_sum!(
        uninitialized_box,                  // Box::from_raw_in return
        boxed_result.bytes,                 // try_new_uninit_in return
        uninitialized_box,                  // new_uninit_in Ok pattern and return
        uninitialized_box,                  // LeafNode/InternalNode::new local
        uninitialized_box,                  // assume_init owned self argument
        initialized_box,                    // assume_init return
        initialized_box,                    // LeafNode/InternalNode::new return
        initialized_box,                    // from_new_leaf/from_new_internal owned argument
        initialized_box,                    // into_non_null_with_allocator owned argument
        initialized_box,                    // into_raw_with_allocator owned argument
        initialized_box,                    // ManuallyDrop::new owned argument
        initialized_box,                    // MaybeDangling::new owned Box argument
        initialized_box,                    // transparent MaybeDangling<Box> return
        size_of::<ManuallyDrop<Box<()>>>(), // returned ManuallyDrop header
        size_of::<ManuallyDrop<Box<()>>>(), // into_raw_with_allocator local
        allocation_tuple,                   // (*mut Node, Global) return
        allocation_tuple                    // (NonNull<Node>, Global) return
    );
    let scratch = checked_sum!(
        size_of::<Layout>(),        // new_uninit_in layout retained over try constructor
        size_of::<Layout>(),        // try_new_uninit_in layout/allocate argument
        allocation_result.bytes,    // Allocator::allocate return envelope
        size_of::<NonNull<[u8]>>(), // Ok allocation pattern
        size_of::<NonNull<[u8]>>(), // cast receiver
        size_of::<NonNull<u8>>(),   // cast return / ptr local
        size_of::<*mut u8>(),       // as_ptr / from_raw_in pointer input
        unique_pointer.bytes,       // from_raw_in's Unique pointer constructor return
        size_of::<*mut u8>(),       // into_raw_with_allocator raw local
        size_of::<&mut ManuallyDrop<Box<()>>>(), // ManuallyDrop deref receiver
        size_of::<&mut ()>(),       // inner MaybeDangling::as_mut receiver
        size_of::<&mut Box<()>>(),  // MaybeDangling::as_mut return
        size_of::<&mut Box<()>>(),  // outer ManuallyDrop deref return
        size_of::<&ManuallyDrop<Box<()>>>(), // allocator field read receiver
        size_of::<&()>(),           // inner MaybeDangling::as_ref receiver
        size_of::<&Box<()>>(),      // MaybeDangling::as_ref return
        size_of::<&Box<()>>(),      // outer ManuallyDrop::deref return
        size_of::<&()>(),           // fieldless Global borrowed field
        size_of::<NonNull<u8>>(),   // into_non_null pattern's pointer
        size_of::<*mut u8>(),       // NonNull::new_unchecked pointer argument
        size_of::<NonNull<u8>>(),   // NonNull::new_unchecked return
        size_of::<bool>()           // T::IS_ZST branch result
    );
    Ok(MapCloneControlStorageData {
        transient_return_bytes: transient,
        declared_counter_scratch_bytes: scratch,
    })
}

fn leaf_initialization_data(layouts: &MapCloneControlLayoutsData) -> Result<usize, RuntimeError> {
    // node.rs73-84: init receives a pointer; parent None and len zero are
    // initialized through raw pointers. The keys/values stay uninitialized.
    Ok(checked_sum!(
        layouts.pointer_bytes,                 // Box::deref_mut receiver
        layouts.pointer_bytes,                 // Box::deref_mut returned MaybeUninit loan
        layouts.pointer_bytes,                 // MaybeUninit::as_mut_ptr receiver
        layouts.pointer_bytes,                 // as_mut_ptr return
        layouts.pointer_bytes,                 // LeafNode::init this argument
        layouts.pointer_bytes,                 // raw parent field pointer
        layouts.optional_parent_pointer_bytes, // ptr::write's None argument
        layouts.pointer_bytes,                 // raw len field pointer
        size_of::<u16>(),                      // ptr::write's zero argument
        size_of::<()>()                        // sequential write/init results
    ))
}

fn parent_link_data(layouts: &MapCloneControlLayoutsData) -> Result<usize, RuntimeError> {
    let index_write = super::initializers::maybe_uninit_write_data::<u16>()?;
    // node.rs989-995,1102-1118,573-577. The Handle is consumed by descend;
    // the resulting mutable child is then borrowed by set_parent_link.
    Ok(checked_sum!(
        layouts.handle_bytes,  // correct_parent_link owned self
        layouts.pointer_bytes, // &self.node to as_internal_ptr
        layouts.pointer_bytes, // returned raw internal pointer
        layouts.pointer_bytes, // NonNull::new_unchecked returned ptr/local
        size_of::<usize>(),    // idx local
        layouts.handle_bytes,  // descend owned self argument
        layouts.pointer_bytes, // descend's as_internal_ptr receiver
        layouts.pointer_bytes, // descend parent_ptr local
        size_of::<&[std::mem::MaybeUninit<NonNull<u8>>; 12]>(), // edges array loan
        size_of::<usize>(),    // get_unchecked index argument
        size_of::<&std::mem::MaybeUninit<NonNull<u8>>>(), // selected edge
        layouts.pointer_bytes, // assume_init_read receiver
        layouts.pointer_bytes, // nested as_ptr receiver
        layouts.pointer_bytes, // as_ptr return
        layouts.pointer_bytes, // ptr::read pointer argument
        size_of::<NonNull<u8>>(), // descended node local
        size_of::<NonNull<u8>>(), // assume_init_read return/local
        layouts.node_ref_bytes, // descend returned mutable child
        layouts.node_ref_bytes, // correct_parent_link child local
        layouts.pointer_bytes, // set_parent_link mutable child receiver
        layouts.pointer_bytes, // owned parent pointer argument
        size_of::<usize>(),    // parent_idx argument
        layouts.pointer_bytes, // set_parent_link as_leaf_ptr receiver
        layouts.pointer_bytes, // returned leaf pointer/local
        layouts.optional_parent_pointer_bytes, // stored Some(parent) input
        size_of::<u16>(),      // cast index input
        size_of::<&mut std::mem::MaybeUninit<u16>>(), // parent_idx.write receiver
        size_of::<&mut u16>(), // parent_idx.write returned field loan
        index_write.transient_return_bytes, // Copy index initializer controls
        index_write.declared_counter_scratch_bytes,
        size_of::<()>() // setter/link results
    ))
}

fn leaf_constructor_data(
    layouts: &MapCloneControlLayoutsData,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    let boxed = box_construction_data(
        layouts.leaf_box_bytes,
        layouts.uninitialized_leaf_box_bytes,
        layouts.allocated_pointer_tuple_bytes,
    )?;
    Ok(MapCloneControlStorageData {
        transient_return_bytes: checked_sum!(
            boxed.transient_return_bytes,
            layouts.node_ref_bytes, // from_new_leaf return
            layouts.node_ref_bytes, // new_leaf return
            layouts.node_ref_bytes, // forget_type owned self
            layouts.node_ref_bytes  // forget_type return (Root::new return is in direct row)
        ),
        declared_counter_scratch_bytes: checked_sum!(
            boxed.declared_counter_scratch_bytes,
            leaf_initialization_data(layouts)?,
            layouts.pointer_bytes, // from_new_leaf destructured node local
            size_of::<usize>(),    // new Root height=0
            size_of::<()>()        // default Global and PhantomData are fieldless
        ),
    })
}

fn internal_constructor_data(
    layouts: &MapCloneControlLayoutsData,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    let boxed = box_construction_data(
        layouts.internal_box_bytes,
        layouts.uninitialized_internal_box_bytes,
        layouts.allocated_pointer_tuple_bytes,
    )?;
    let root_unit = FieldBound::record(&[
        FieldBound {
            bytes: layouts.node_ref_bytes,
            alignment: align_of::<usize>(),
        },
        FieldBound::of::<()>(),
    ])?;
    Ok(MapCloneControlStorageData {
        transient_return_bytes: checked_sum!(
            boxed.transient_return_bytes,
            layouts.node_ref_bytes, // mem::replace ptr::read old root/local
            layouts.node_ref_bytes, // take_mut change closure owned input
            layouts.node_ref_bytes, // new_internal owned child argument
            layouts.node_ref_bytes, // from_new_internal return
            layouts.node_ref_bytes, // new_internal return
            layouts.node_ref_bytes, // forget_type owned input
            layouts.node_ref_bytes, // forget_type return
            root_unit.bytes,        // replace's closure returned (Root, ())
            layouts.node_ref_bytes  // ptr::write's owned replacement root
        ),
        declared_counter_scratch_bytes: checked_sum!(
            boxed.declared_counter_scratch_bytes,
            leaf_initialization_data(layouts)?,
            layouts.pointer_bytes,    // push_internal_level &mut root receiver
            layouts.pointer_bytes,    // take_mut's mutable root argument
            layouts.pointer_bytes,    // replace's mutable root argument
            layouts.pointer_bytes,    // ptr::read input
            layouts.pointer_bytes,    // ptr::write destination
            layouts.pointer_bytes,    // new_node.edges[0] field receiver
            size_of::<NonNull<u8>>(), // child edge pointer write input
            size_of::<&mut NonNull<u8>>(), // edge MaybeUninit::write return
            layouts.optional_height_bytes, // NonZero::new return
            layouts.nonzero_height_bytes, // unwrapped NonZero return
            layouts.nonzero_height_bytes, // from_new_internal height argument
            layouts.pointer_bytes,    // from_new_internal destructured node
            size_of::<usize>(),       // returned height.into value
            layouts.node_ref_bytes,   // this local / borrow_mut receiver
            layouts.node_ref_bytes,   // this.borrow_mut return
            layouts.pointer_bytes,    // correct_all_childrens_parent_links receiver
            size_of::<usize>(),       // actual new internal len=0
            size_of::<std::ops::RangeInclusive<usize>>(), // 0..=len return/input
            size_of::<std::ops::RangeInclusive<usize>>(), // for's owned range iterator
            size_of::<Option<usize>>(), // range.next return
            size_of::<usize>(),       // selected index i
            layouts.node_ref_bytes,   // self.reborrow_mut return
            layouts.handle_bytes,     // Handle::new_edge return
            parent_link_data(layouts)?, // new internal has exactly one initialized edge
            layouts.node_ref_bytes,   // final mutable out_node return
            size_of::<bool>(),        // sequential height/index validity predicates
            size_of::<()>()           // fieldless Global/closures/PanicGuard and results
        ),
    })
}

fn length_view_data(layouts: &MapCloneControlLayoutsData) -> Result<usize, RuntimeError> {
    // node.rs285-290 -> as_leaf_ptr -> usize::from(u16).
    Ok(checked_sum!(
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        size_of::<u16>(),
        size_of::<usize>()
    ))
}

fn node_selector_views_data(layouts: &MapCloneControlLayoutsData) -> Result<usize, RuntimeError> {
    // Branch-local calls: leaf has one first_edge and one terminal right_kv;
    // internal has two first_edge calls, one terminal right_kv, and the three
    // len calls of initial correct_all/correct_childrens/new_edge. Their max
    // has six len views. Actual nonempty node count is bounded by entry count.
    Ok(checked_sum!(
        layouts.node_ref_bytes,     // force owned self input
        size_of::<usize>(),         // force height/discriminant input
        layouts.node_ref_bytes,     // first first_edge owned self
        layouts.node_ref_bytes,     // first Handle::new_edge node argument
        layouts.handle_bytes,       // first new_edge return
        layouts.handle_bytes,       // first first_edge return
        layouts.node_ref_bytes,     // second first_edge (internal branch)
        layouts.node_ref_bytes,     // second new_edge node argument
        layouts.handle_bytes,       // second new_edge return
        layouts.handle_bytes,       // second first_edge return
        layouts.handle_bytes,       // terminal right_kv owned self, Err branch
        length_view_data(layouts)?, // first_edge/new_edge #1
        length_view_data(layouts)?, // first_edge/new_edge #2
        length_view_data(layouts)?, // terminal right_kv
        length_view_data(layouts)?, // correct_all_childrens_parent_links
        length_view_data(layouts)?, // correct_childrens_parent_links assertion
        length_view_data(layouts)?, // corrected edge new_edge assertion
        size_of::<usize>(),         // sequential constructor index argument
        size_of::<bool>()           // sequential branch/assertion predicates
    ))
}

fn entry_selector_views_data<K, V>(
    layouts: &MapCloneControlLayoutsData,
) -> Result<usize, RuntimeError> {
    // right_kv -> new_kv, into_kv -> into_leaf, right_edge -> new_edge,
    // plus the leaf/internal push selector bodies. Leaf has six len calls
    // (two right_kv/new_kv, into_kv, right_edge/new_edge, push/new_kv,
    // into_val_mut). Internal has five. Return/consumer slots already named
    // by the reviewed direct row stay separate from these helper arguments.
    let common = checked_sum!(
        layouts.handle_bytes,                     // successful right_kv owned self
        layouts.node_ref_bytes,                   // new_kv's owned node argument
        size_of::<usize>(),                       // new_kv index input
        layouts.handle_bytes,                     // new_kv return to right_kv
        layouts.handle_bytes,                     // into_kv owned self
        layouts.node_ref_bytes,                   // into_leaf owned self
        layouts.pointer_bytes,                    // into_leaf as_leaf_ptr receiver
        layouts.pointer_bytes,                    // into_leaf raw pointer return/local
        layouts.pointer_bytes,                    // returned shared LeafNode loan
        layouts.pointer_bytes,                    // into_kv leaf local
        size_of::<&[std::mem::MaybeUninit<K>]>(), // key-area slice loan geometry
        size_of::<&std::mem::MaybeUninit<K>>(),   // selected key field
        layouts.pointer_bytes,                    // assume_init_ref K receiver
        layouts.pointer_bytes,                    // nested MaybeUninit<K>::as_ptr receiver
        layouts.pointer_bytes,                    // nested as_ptr returned pointer
        layouts.pointer_bytes,                    // assume_init_ref returned K loan
        layouts.pointer_bytes,                    // into_kv k local
        size_of::<&[std::mem::MaybeUninit<V>]>(), // value-area slice loan geometry
        size_of::<&std::mem::MaybeUninit<V>>(),   // selected value field
        layouts.pointer_bytes,                    // assume_init_ref V receiver
        layouts.pointer_bytes,                    // nested MaybeUninit<V>::as_ptr receiver
        layouts.pointer_bytes,                    // nested as_ptr returned pointer
        layouts.pointer_bytes,                    // assume_init_ref returned V loan
        layouts.pointer_bytes,                    // into_kv v local
        layouts.handle_bytes,                     // right_edge owned self
        layouts.node_ref_bytes,                   // right_edge new_edge node argument
        size_of::<usize>(),                       // right-edge index input
        layouts.handle_bytes,                     // new_edge return
        // len_mut -> as_leaf_mut -> as_leaf_ptr, with the returned u16 loan.
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        size_of::<&mut u16>(),
        // key_area_mut's receiver/index and leaf/slice/selected-field loans.
        layouts.pointer_bytes,
        size_of::<usize>(),
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        size_of::<&mut [std::mem::MaybeUninit<K>]>(),
        layouts.pointer_bytes,
        // val_area_mut follows the same actual typed call sequence.
        layouts.pointer_bytes,
        size_of::<usize>(),
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        size_of::<&mut [std::mem::MaybeUninit<V>]>(),
        layouts.pointer_bytes,
        length_view_data(layouts)?, // right_kv len
        length_view_data(layouts)?, // successful new_kv assertion
        length_view_data(layouts)?, // into_kv assertion
        length_view_data(layouts)?, // right_edge new_edge assertion
        size_of::<usize>(),
        size_of::<bool>(),
        size_of::<()>()
    );
    let internal_push = checked_sum!(
        // Internal edge_area_mut -> as_internal_mut -> as_internal_ptr.
        layouts.pointer_bytes,
        size_of::<usize>(),
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        size_of::<&mut [std::mem::MaybeUninit<NonNull<u8>>]>(),
        layouts.pointer_bytes,
        length_view_data(layouts)? // pushed internal edge new_edge assertion
    );
    let leaf_push = checked_sum!(
        // Leaf into_val_mut -> into_leaf_mut -> pointer/field loans. Its
        // outer Handle self and returned &mut V were closed in reviewed v2.
        layouts.node_ref_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        layouts.pointer_bytes,
        size_of::<&mut [std::mem::MaybeUninit<V>]>(),
        layouts.pointer_bytes,
        layouts.pointer_bytes,      // into_val_mut assume_init_mut receiver
        layouts.pointer_bytes,      // nested as_mut_ptr receiver
        layouts.pointer_bytes,      // nested as_mut_ptr return
        layouts.pointer_bytes,      // assume_init_mut returned V loan
        length_view_data(layouts)?, // pushed leaf new_kv assertion
        length_view_data(layouts)?  // into_val_mut assertion
    );
    Ok(checked_sum!(common, leaf_push.max(internal_push)))
}

/// Names fixed data/result/layout controls before the map constructor query.
pub(super) fn constructor_counter_scratch_data() -> usize {
    super::initializers::counter_scratch_data()
        + size_of::<MapCloneControlStorageData>() // key initializer row
        + size_of::<MapCloneControlStorageData>() // value initializer row
        + size_of::<MapCloneControlStorageData>() // child-edge initializer row
        + size_of::<MapCloneControlStorageData>() // subtree ManuallyDrop row
        + size_of::<MapCloneControlStorageData>() // parent-index initializer row
        + size_of::<Result<MapCloneControlStorageData,RuntimeError>>()
        + size_of::<MapCloneControlLayoutsData>()
        + size_of::<MapCloneControlStorageData>() // direct row retained over helper work
        + size_of::<MapCloneControlStorageData>() // boxed/helper local
        + size_of::<MapCloneControlStorageData>() // leaf constructor local
        + size_of::<MapCloneControlStorageData>() // internal constructor local
        + size_of::<MapCloneControlStorageData>() // combined result initializer
        + size_of::<Result<MapCloneControlStorageData, RuntimeError>>()
        + size_of::<[FieldBound; 3]>() // Box result, allocation result, Unique pointer
        + size_of::<FieldBound>() // Root/unit tuple
        + size_of::<[FieldBound; 2]>() // actual source-field argument arrays
        + size_of::<[usize; 3]>() // Box/tuple layout arguments
        + size_of::<[usize; 2]>() // input length and maximum
        + size_of::<[usize; 6]>() // helper T/S, whole T/S and node/entry helper rows
        + size_of::<[usize; 3]>() // selector common, leaf and internal branch locals
        + size_of::<[usize; 2]>() // checked_sum previous/next scalar
        + size_of::<Result<usize, RuntimeError>>()
        + size_of::<Option<usize>>()
        + size_of::<&MapCloneControlLayoutsData>()
        + size_of::<&MapCloneControlLayoutsData>() // nested concrete helper input
        + size_of::<bool>()
}

/// Composes actual direct, constructor, link and move-initializer windows.
///
/// Child K/V Clone implementations and requested backing remain separate.
///
/// # Errors
/// Refuses incompatible pinned geometry, checked overflow or row exhaustion.
pub(super) fn map_constructor_storage_data<K: Clone, V: Clone>(
    initialized_len: usize,
    maximum: usize,
) -> Result<MapCloneControlStorageData, RuntimeError> {
    let direct = map_clone_control_storage_data::<K, V>(initialized_len, maximum)?;
    let layouts = map_clone_control_layouts_data::<K, V>()?;
    let leaf = leaf_constructor_data(&layouts)?;
    let internal = internal_constructor_data(&layouts)?;
    let node_views = node_selector_views_data(&layouts)?;
    let entry_views = entry_selector_views_data::<K, V>(&layouts)?;
    let key_write = super::initializers::maybe_uninit_write_data::<K>()?;
    let value_write = super::initializers::maybe_uninit_write_data::<V>()?;
    let edge_write = super::initializers::maybe_uninit_write_data::<NonNull<u8>>()?;
    let subtree_move = super::initializers::manually_drop_data::<BTreeMap<K, V>>()?;
    let transient = checked_sum!(
        direct.transient_return_bytes,
        initialized_len
            .checked_mul(checked_sum!(
                key_write.transient_return_bytes,
                value_write.transient_return_bytes
            ))
            .ok_or(RuntimeError::ResourceLimit)?,
        initialized_len
            .checked_mul(edge_write.transient_return_bytes)
            .ok_or(RuntimeError::ResourceLimit)?, // new internal edge[0] write
        initialized_len
            .checked_mul(edge_write.transient_return_bytes)
            .ok_or(RuntimeError::ResourceLimit)?, // pushed internal edge write
        initialized_len
            .checked_mul(subtree_move.transient_return_bytes)
            .ok_or(RuntimeError::ResourceLimit)?,
        if initialized_len == 0 {
            layouts.optional_root_bytes
        } else {
            initialized_len
                .checked_mul(
                    leaf.transient_return_bytes
                        .max(internal.transient_return_bytes),
                )
                .ok_or(RuntimeError::ResourceLimit)?
        }
    );
    let scratch = checked_sum!(
        direct.declared_counter_scratch_bytes,
        constructor_counter_scratch_data(),
        initialized_len
            .checked_mul(checked_sum!(
                key_write.declared_counter_scratch_bytes,
                value_write.declared_counter_scratch_bytes
            ))
            .ok_or(RuntimeError::ResourceLimit)?,
        initialized_len
            .checked_mul(edge_write.declared_counter_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?, // initial child edge
        initialized_len
            .checked_mul(edge_write.declared_counter_scratch_bytes)
            .ok_or(RuntimeError::ResourceLimit)?, // pushed child edge
        initialized_len
            .checked_mul(size_of::<NonNull<u8>>())
            .ok_or(RuntimeError::ResourceLimit)?, // pushed edge.write copied pointer input
        initialized_len
            .checked_mul(
                leaf.declared_counter_scratch_bytes
                    .max(internal.declared_counter_scratch_bytes)
            )
            .ok_or(RuntimeError::ResourceLimit)?,
        initialized_len
            .checked_mul(node_views)
            .ok_or(RuntimeError::ResourceLimit)?,
        initialized_len
            .checked_mul(entry_views)
            .ok_or(RuntimeError::ResourceLimit)?,
        // One new edge is linked after each actual internal KV push. Actual
        // initialized entries bound this separately from the constructor's link.
        initialized_len
            .checked_mul(parent_link_data(&layouts)?)
            .ok_or(RuntimeError::ResourceLimit)?,
        // unwrap_or_else's closure captures only &alloc; it is created at the
        // actual per-internal-entry expression even though valid subroot is Some.
        initialized_len
            .checked_mul(size_of::<&()>())
            .ok_or(RuntimeError::ResourceLimit)?
    );
    if transient
        .checked_add(scratch)
        .ok_or(RuntimeError::ResourceLimit)?
        > maximum
    {
        return Err(RuntimeError::ResourceLimit);
    }
    Ok(MapCloneControlStorageData {
        transient_return_bytes: transient,
        declared_counter_scratch_bytes: scratch,
    })
}
