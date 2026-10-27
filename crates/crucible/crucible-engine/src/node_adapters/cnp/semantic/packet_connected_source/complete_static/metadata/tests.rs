//! Checks original static row backing without claiming installed graph authority.

use super::*;
use crate::node_adapters::cnp::PacketCompleteSemanticSource;
use crucible_node_format::canonical;

fn retained_rows() -> CompleteInputStaticRows {
    let reference = canonical::content_ref(b"static DATA", "application/octet-stream").unwrap();
    let mut bytes = Vec::with_capacity(89);
    bytes.extend_from_slice(b"static DATA");
    let mut dependencies = Vec::with_capacity(5);
    dependencies.push(reference.clone());
    dependencies.push(reference.clone());
    let mut rows = Vec::with_capacity(7);
    rows.push((InputPayload { reference, bytes }, dependencies));
    CompleteInputStaticRows {
        rows,
        complete: false,
        failed: true,
    }
}

#[test]
fn static_capacity_matches_original_backing_without_duplicating_inline_header() {
    let original = retained_rows();
    let legacy = original
        .storage_with_error::<RuntimeError>(usize::MAX)
        .unwrap();
    let bytes = legacy - size_of::<CompleteInputStaticRows>();
    let pointers = (
        original.rows.as_ptr(),
        original.rows[0].0.bytes.as_ptr(),
        original.rows[0].1.as_ptr(),
    );
    let mut census = OriginalOwnerCapacityMetadataData::new(usize::MAX, None);

    original.record_retained_capacity_data(&mut census).unwrap();
    let facts = census.finish();

    assert_eq!(facts.capacity_records, 15);
    assert_eq!(facts.vector_banks, 3);
    assert_eq!(facts.string_banks, 12);
    assert_eq!(
        facts.vector_capacity_bytes,
        original.rows.capacity() * size_of::<(InputPayload, Vec<ContentRef>)>()
            + original.rows[0].0.bytes.capacity()
            + original.rows[0].1.capacity() * size_of::<ContentRef>()
    );
    // Three full references, one payload header and its two child Vecs.
    assert_eq!(facts.observed_nodes, 24 + original.rows[0].0.bytes.len());
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts, bytes
        ),
        Ok(bytes)
    );
    assert_eq!(
        PacketCompleteSemanticSource::complete_retained_metadata_storage_precredit_data(
            &facts,
            bytes - 1
        ),
        Err(RuntimeError::ResourceLimit)
    );
    assert_eq!(
        (
            original.rows.as_ptr(),
            original.rows[0].0.bytes.as_ptr(),
            original.rows[0].1.as_ptr()
        ),
        pointers
    );
    assert!(!original.complete);
    assert!(original.failed);
}

#[test]
fn static_short_rows_keep_the_previous_owner_and_original_partial_body() {
    let original = retained_rows();
    let previous = String::with_capacity(173);
    let mut census = OriginalOwnerCapacityMetadataData::new(7, None);
    census.observe(&previous).unwrap();

    let result = original.record_retained_capacity_data(&mut census);
    let facts = census.finish();

    assert_eq!(result, Err(RuntimeError::ResourceLimit));
    assert_eq!(facts.capacity_records, 7);
    assert_eq!(facts.vector_banks, 2);
    assert_eq!(facts.string_banks, 5);
    assert!(facts.string_capacity_bytes >= previous.capacity());
    assert_eq!(
        facts.vector_capacity_bytes,
        original.rows.capacity() * size_of::<(InputPayload, Vec<ContentRef>)>()
            + original.rows[0].0.bytes.capacity()
    );
    assert!(!original.complete);
    assert!(original.failed);
}
