//! Checks actual capacity geometry, repeated views and the separate packet limit.

use super::*;
use crate::node_contract::{OwnerIdentity, SavedRuntimeActivation};
use crucible_node_format::{HashRef, Id, Phase, Position, U64};
use std::{collections::BTreeMap, mem::align_of, rc::Rc};

fn activation() -> SavedRuntimeActivation {
    let mut algorithm = String::with_capacity(113);
    algorithm.push_str("sha256");
    let mut owners = Vec::with_capacity(11);
    owners.push(OwnerIdentity {
        owner: Id::new("owner").unwrap(),
        incarnation: Id::new("incarnation").unwrap(),
        generation: U64::new(3),
    });
    SavedRuntimeActivation {
        generation: U64::new(7),
        activation_id: Id::new("activation").unwrap(),
        world_binding_hash: HashRef {
            algorithm,
            domain: "world".into(),
            digest: "original".into(),
        },
        owners,
        boundary: Position::new(U64::new(5), U64::new(0), Phase::BoundaryControl),
    }
}

#[test]
fn saved_activation_keeps_original_spare_capacity_and_independent_owner_strings() {
    let value = activation();
    let mut census = OriginalOwnerCapacityMetadataData::new(7, None);
    census.observe(&value).unwrap();
    let facts = census.finish();
    let hash = &value.world_binding_hash;
    let owner = &value.owners[0];

    assert_eq!(facts.capacity_records, 7);
    assert_eq!(facts.vector_banks, 1);
    assert_eq!(
        facts.vector_capacity_bytes,
        value.owners.capacity() * size_of::<OwnerIdentity>()
    );
    assert_eq!(facts.string_banks, 6);
    assert_eq!(
        facts.string_capacity_bytes,
        value.activation_id.allocated_capacity()
            + hash.algorithm.capacity()
            + hash.domain.capacity()
            + hash.digest.capacity()
            + owner.owner.allocated_capacity()
            + owner.incarnation.allocated_capacity()
    );
    assert_eq!(facts.observed_nodes, 0);
    assert!(value.world_binding_hash.algorithm.capacity() >= 113);
}

#[derive(Eq, PartialEq, Ord, PartialOrd)]
#[repr(align(64))]
struct Aligned;

impl OriginalRestoredOwnerCapacityWalk for Aligned {
    fn capacities(
        &self,
        _depth: usize,
        _sink: &mut dyn FnMut(OriginalRestoredOwnerCapacityRow) -> Result<(), RuntimeError>,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }
}

#[test]
fn actual_empty_trees_keep_tuple_padding_and_zero_sized_alignment() {
    let padded = BTreeMap::<u8, Aligned>::new();
    let zero = BTreeMap::<Aligned, Aligned>::new();
    let mut census = OriginalOwnerCapacityMetadataData::new(2, None);
    census.observe(&padded).unwrap();
    census.observe(&zero).unwrap();
    let facts = census.finish();

    assert_eq!(facts.tree_containers, 2);
    assert_eq!(facts.tree_entries, 0);
    assert_eq!(
        facts.maximum_tree_key_value_bytes,
        size_of::<(u8, Aligned)>()
    );
    assert_eq!(
        facts.maximum_tree_entry_alignment,
        align_of::<(Aligned, Aligned)>()
    );
    assert_eq!(facts.capacity_records, 2);
}

#[test]
fn actual_shared_views_and_boxed_payloads_receive_no_alias_discount() {
    let mut text = String::with_capacity(257);
    text.push('x');
    let shared = Rc::new(text);
    let boxed = Box::new(Id::new("boxed").unwrap());
    let mut census = OriginalOwnerCapacityMetadataData::new(6, None);
    census.observe(&shared).unwrap();
    census.observe(&shared).unwrap();
    census.observe(&boxed).unwrap();
    let facts = census.finish();

    assert_eq!(facts.shared_backing_views, 2);
    assert_eq!(facts.shared_value_bytes, 2 * size_of::<String>());
    assert_eq!(facts.maximum_shared_value_alignment, align_of::<String>());
    assert_eq!(facts.boxed_value_bytes, size_of::<Id>());
    assert_eq!(
        facts.string_capacity_bytes,
        2 * shared.capacity() + boxed.allocated_capacity()
    );
    assert_eq!(facts.capacity_records, 6);
    assert_eq!(Rc::strong_count(&shared), 1);
}

#[test]
fn packet_capacity_census_does_not_enlarge_the_legacy_common_reader() {
    use super::super::{MAXIMUM_ROWS, OriginalRestoredOwnerCapacityRows};

    let values = vec![String::new(); MAXIMUM_ROWS];
    let mut census = OriginalOwnerCapacityMetadataData::new(MAXIMUM_ROWS + 1, None);
    census.observe(&values).unwrap();
    let facts = census.finish();
    assert_eq!(facts.capacity_records, MAXIMUM_ROWS + 1);
    assert_eq!(
        facts.vector_capacity_bytes,
        values.capacity() * size_of::<String>()
    );
    assert_eq!(
        OriginalRestoredOwnerCapacityRows(&values).metadata_demand_data(),
        Err(RuntimeError::ResourceLimit)
    );

    let mut short = OriginalOwnerCapacityMetadataData::new(MAXIMUM_ROWS, None);
    assert_eq!(short.observe(&values), Err(RuntimeError::ResourceLimit));
    assert_eq!(short.finish().capacity_records, MAXIMUM_ROWS);
    assert_eq!(values.len(), MAXIMUM_ROWS);
}

#[test]
fn pointer_and_alias_data_never_enter_four_field_packet_rows() {
    let value = Rc::new(Aligned);
    let mut records = Vec::new();
    value
        .capacities(0, &mut |row| {
            records.push(packet_row_data(row)?);
            Ok(())
        })
        .unwrap();

    assert_eq!(
        serde_json::to_string(&records).unwrap(),
        "[[\"shared\",0,1,64]]"
    );
    assert_eq!(Rc::strong_count(&value), 1);
}

#[test]
fn malformed_row_geometry_and_population_overflow_are_refused() {
    let mut row = OriginalRestoredOwnerCapacityRow::byte_buffer_data(3, 4).unwrap();
    row.capacity = Some(2);
    assert!(packet_row_data(row).is_err());
    let mut row = OriginalRestoredOwnerCapacityRow::tree_population_data::<u8, u64>(3);
    row.capacity = Some(3);
    assert!(packet_row_data(row).is_err());

    let mut census = OriginalOwnerCapacityMetadataData::new(1, None);
    assert!(
        census
            .record(MetadataCapacityRecord {
                kind: MetadataRecordKind::Vector,
                extent: usize::MAX,
                element_bytes: 2,
                alignment: 8,
            })
            .is_err()
    );
    assert_eq!(census.finish().capacity_records, 0);
    let mut target = RetainedProtocolMetadataFacts {
        shared_backing_views: usize::MAX,
        ..Default::default()
    };
    let additional = RetainedProtocolMetadataFacts {
        shared_backing_views: 1,
        ..Default::default()
    };
    assert_eq!(
        merge_capacity_metadata_data(&mut target, &additional),
        Err(RuntimeError::ResourceLimit)
    );
}

#[test]
fn independently_observed_geometry_merges_without_widening_by_byte_count() {
    let mut target = RetainedProtocolMetadataFacts {
        tree_containers: 1,
        tree_entries: 2,
        maximum_tree_key_value_bytes: 17,
        maximum_tree_entry_alignment: 8,
        ..Default::default()
    };
    let additional = RetainedProtocolMetadataFacts {
        tree_containers: 1,
        tree_entries: 3,
        maximum_tree_key_value_bytes: 1,
        maximum_tree_entry_alignment: 64,
        shared_value_bytes: 1_000_000,
        shared_backing_views: 2,
        maximum_shared_value_alignment: 128,
        capacity_records: 3,
        ..Default::default()
    };
    merge_capacity_metadata_data(&mut target, &additional).unwrap();

    assert_eq!(target.tree_containers, 2);
    assert_eq!(target.tree_entries, 5);
    assert_eq!(target.maximum_tree_key_value_bytes, 17);
    assert_eq!(target.maximum_tree_entry_alignment, 64);
    assert_eq!(target.maximum_shared_value_alignment, 128);
    assert_eq!(target.shared_backing_views, 2);
    assert_eq!(target.capacity_records, 3);
}
