//! Checks capacity DATA from the runtime issuer in the existing synthetic models.
//!
//! These inherited native models qualify no real Source installation, native
//! class, completed Initial or one-use handoff. The census only borrows the
//! runtime-issued immutable lineage and retains every original allocation view.

use super::*;
use crate::node_contract::restored_owner_history::{
    OriginalOwnerCapacityMetadataData, merge_capacity_metadata_data,
};

#[test]
fn lineage_capacity_keeps_both_roots_and_each_repeated_core_view() {
    let (mut runtime, _, _, batch) = fixture();
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        .unwrap()
        .unwrap();
    let pointers = (
        lineage.publications().as_ptr(),
        lineage.original().payloads().as_ptr(),
    );
    let mut batch_census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);
    batch_census.observe(lineage.original()).unwrap();
    let batch_facts = batch_census.finish();
    let mut first = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    first.observe(&lineage).unwrap();
    let facts = first.finish();

    assert_eq!(
        facts.shared_backing_views,
        batch_facts.shared_backing_views + 2
    );
    assert!(
        facts.shared_value_bytes
            >= batch_facts.shared_value_bytes + std::mem::size_of::<RuntimeInputBatch>()
    );
    assert!(
        facts.vector_capacity_bytes
            >= batch_facts.vector_capacity_bytes
                + lineage.publications().len() * std::mem::size_of::<OriginalPublicationClaim>()
    );
    assert_eq!(facts.observed_nodes, 0);
    let retained = lineage.retained_copy();
    let mut repeated = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    repeated.observe(&lineage).unwrap();
    repeated.observe(&retained).unwrap();
    let mut expected = facts;
    merge_capacity_metadata_data(&mut expected, &facts).unwrap();

    assert_eq!(repeated.finish(), expected);
    assert_eq!(
        (
            retained.publications().as_ptr(),
            retained.original().payloads().as_ptr()
        ),
        pointers
    );
    assert_eq!(lineage.original().deliveries(), batch.deliveries());
}

#[test]
fn lineage_capacity_refusal_preserves_the_prior_row_and_real_data_root() {
    let (mut runtime, _, _, batch) = fixture();
    let lineage = runtime
        .prepare_original_input_lineage(&batch)
        .unwrap()
        .unwrap();
    let original = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(2, None);
    census.observe(&original).unwrap();

    let result = census.observe(&lineage);
    let facts = census.finish();

    assert_eq!(result, Err(RuntimeError::ResourceLimit));
    assert_eq!(facts.capacity_records, 2);
    assert_eq!(facts.string_banks, 1);
    assert_eq!(facts.string_capacity_bytes, original.capacity());
    assert_eq!(facts.shared_backing_views, 1);
    assert_eq!(facts.vector_banks, 0);
    assert_eq!(lineage.original().deliveries(), batch.deliveries());
}
