//! Exercises ordinary typed layout bounds and real map clones; controls UNRUN.

use super::*;
use serde_json::{Value, json};

#[test]
fn field_and_enum_bounds_cover_actual_representative_layouts() {
    type Fields = (usize, NonNull<u8>, std::marker::PhantomData<()>);
    type Handles = (Fields, usize, std::marker::PhantomData<()>);
    let node = FieldBound::record(&[
        FieldBound::of::<usize>(),
        FieldBound::of::<NonNull<u8>>(),
        FieldBound::of::<std::marker::PhantomData<()>>(),
    ])
    .unwrap();
    let handle = FieldBound::record(&[
        node,
        FieldBound::of::<usize>(),
        FieldBound::of::<std::marker::PhantomData<()>>(),
    ])
    .unwrap();

    // These are actual public representative types for the bound arithmetic,
    // not a claim that tests can name liballoc's private NodeRef or Handle ABI.
    let concrete = map_clone_control_layouts_data::<String, Value>().unwrap();
    assert_eq!(concrete.leaf_box_bytes, size_of::<Box<()>>());
    assert_eq!(concrete.internal_box_bytes, size_of::<Box<()>>());
    assert_eq!(
        concrete.uninitialized_leaf_box_bytes,
        size_of::<Box<std::mem::MaybeUninit<()>>>()
    );
    assert_eq!(
        concrete.uninitialized_internal_box_bytes,
        size_of::<Box<std::mem::MaybeUninit<()>>>()
    );
    assert!(concrete.allocated_pointer_tuple_bytes >= size_of::<(NonNull<u8>, ())>());
    assert!(concrete.optional_parent_pointer_bytes >= size_of::<Option<NonNull<u8>>>());
    assert!(concrete.parent_link_bytes >= size_of::<(NonNull<u8>, u16)>());
    assert_eq!(
        concrete.nonzero_height_bytes,
        size_of::<std::num::NonZeroUsize>()
    );
    assert_eq!(
        concrete.optional_height_bytes,
        size_of::<Option<std::num::NonZeroUsize>>()
    );
    assert_eq!(concrete.borrowed_value_bytes, size_of::<&mut Value>());

    assert!(node.bytes >= size_of::<Fields>());
    assert!(handle.bytes >= size_of::<Handles>());
    assert!(
        FieldBound::two_variant(node, node).unwrap().bytes >= size_of::<Result<Fields, Fields>>()
    );
    assert!(
        FieldBound::two_variant(handle, handle).unwrap().bytes
            >= size_of::<Result<Handles, Handles>>()
    );
    assert!(
        FieldBound::two_variant(FieldBound::of::<()>(), node)
            .unwrap()
            .bytes
            >= size_of::<Option<Fields>>()
    );
    assert_eq!(
        FieldBound::record(&[FieldBound {
            bytes: 0,
            alignment: 3
        }]),
        Err(RuntimeError::InvalidReceipt)
    );
    assert!(
        FieldBound::record(&[FieldBound {
            bytes: usize::MAX,
            alignment: 8
        }])
        .is_err()
    );
}

#[test]
fn actual_empty_leaf_and_internal_size_maps_keep_exact_and_one_short_rows() {
    for entries in [0usize, 1, 64] {
        let original: BTreeMap<String, Value> = (0..entries)
            .map(|index| {
                (
                    format!("key-{index:03}"),
                    json!({"index": index, "array": ["data", true, null]}),
                )
            })
            .collect();
        let row =
            map_clone_control_storage_data::<String, Value>(original.len(), usize::MAX).unwrap();
        let peak = row.transient_return_bytes + row.declared_counter_scratch_bytes;

        assert_eq!(
            map_clone_control_storage_data::<String, Value>(original.len(), peak).unwrap(),
            row
        );
        assert_eq!(
            map_clone_control_storage_data::<String, Value>(original.len(), peak - 1),
            Err(RuntimeError::ResourceLimit)
        );
        let cloned = original.clone();

        assert_eq!(cloned, original);
        assert_eq!(original.len(), entries);
        assert_ne!(&cloned as *const _, &original as *const _);
        assert!(row.transient_return_bytes >= 2 * size_of::<BTreeMap<String, Value>>());
        assert!(row.declared_counter_scratch_bytes >= map_clone_control_counter_scratch_data());
        // Capacity11 is the pinned liballoc source constant.64 initialized
        // entries require internal nodes, while this test observes public data.
        if entries == 64 {
            assert!(entries > 11);
            assert!(
                row.transient_return_bytes
                    > map_clone_control_storage_data::<String, Value>(1, usize::MAX)
                        .unwrap()
                        .transient_return_bytes
            );
        }
    }
}

#[test]
fn geometry_supports_actual_overaligned_and_zero_sized_payloads() {
    #[repr(align(4096))]
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Aligned(u8);

    let layouts = map_clone_control_layouts_data::<usize, Aligned>().unwrap();
    let empty = map_clone_control_storage_data::<usize, ()>(0, usize::MAX).unwrap();
    let original: BTreeMap<usize, Aligned> =
        [(1, Aligned(7)), (2, Aligned(9))].into_iter().collect();
    let row = map_clone_control_storage_data::<usize, Aligned>(original.len(), usize::MAX).unwrap();

    assert!(layouts.owned_key_value_bytes >= size_of::<(usize, Aligned)>());
    assert!(row.transient_return_bytes >= original.len() * layouts.owned_key_value_bytes);
    assert!(empty.transient_return_bytes >= 2 * size_of::<BTreeMap<usize, ()>>());
    assert_eq!(original.clone(), original);
}

#[test]
fn unsupported_public_geometry_and_count_overflow_fail_closed() {
    assert_eq!(
        require_profile(
            Layout::new::<u32>(),
            Layout::new::<*const ()>(),
            Layout::new::<BTreeMap<String, Value>>()
        ),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert_eq!(
        require_profile(
            Layout::new::<usize>(),
            Layout::new::<u16>(),
            Layout::new::<BTreeMap<String, Value>>()
        ),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert_eq!(
        require_profile(
            Layout::new::<usize>(),
            Layout::new::<*const ()>(),
            Layout::new::<[usize; 4]>()
        ),
        Err(RuntimeError::UnsupportedFacet)
    );
    assert_eq!(
        map_clone_control_storage_data::<String, Value>(usize::MAX, usize::MAX),
        Err(RuntimeError::ResourceLimit)
    );
}

#[test]
fn actual_map_constructor_rows_fund_empty_leaf_and_internal_clone_routes() {
    for entries in [0usize, 1, 64] {
        let original: BTreeMap<String, Value> = (0..entries)
            .map(|index| {
                (
                    format!("constructor-{index:03}"),
                    json!({"nested":[index,true,null]}),
                )
            })
            .collect();
        let direct =
            map_clone_control_storage_data::<String, Value>(original.len(), usize::MAX).unwrap();
        let complete =
            map_clone_constructor_storage_data::<String, Value>(original.len(), usize::MAX)
                .unwrap();
        let peak = complete.transient_return_bytes + complete.declared_counter_scratch_bytes;

        assert!(complete.transient_return_bytes >= direct.transient_return_bytes);
        assert!(complete.declared_counter_scratch_bytes > direct.declared_counter_scratch_bytes);
        assert_eq!(
            map_clone_constructor_storage_data::<String, Value>(original.len(), peak).unwrap(),
            complete
        );
        assert_eq!(
            map_clone_constructor_storage_data::<String, Value>(original.len(), peak - 1),
            Err(RuntimeError::ResourceLimit)
        );
        assert_eq!(original.clone(), original);
    }
}
