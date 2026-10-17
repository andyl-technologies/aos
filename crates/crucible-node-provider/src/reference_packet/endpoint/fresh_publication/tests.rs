//! Checks retained partial owners without fabricating a completed boot or query.

use super::*;

// crucible-lint: allow panic-shortcut -- exact partial owner retention is the observation.
#[test]
fn incomplete_report_transition_keeps_original_schema_and_raw_banks() {
    let mut publication = NativeFreshReportPublication::new();
    assert!(publication.is_unstarted());
    let mut schema = String::with_capacity(211);
    schema.push_str(PACKET_FRESH_RESTORE_ALLOCATION_REPORT);
    publication.schema = Some(schema);
    publication.raw = Vec::with_capacity(1021);
    publication
        .raw
        .extend_from_slice(b"retained partial canonical report");
    let raw_pointer = publication.raw.as_ptr();
    let schema_pointer = publication.schema.as_ref().map(|schema| schema.as_ptr());

    assert!(publication.assemble_report().is_err());

    assert_eq!(publication.raw.as_ptr(), raw_pointer);
    assert_eq!(publication.raw, b"retained partial canonical report");
    assert_eq!(
        publication.schema.as_ref().map(|schema| schema.as_ptr()),
        schema_pointer
    );
    assert!(publication.report.is_none());
    assert!(publication.completed_record.is_none());
    assert!(!publication.is_unstarted());
}

// crucible-lint: allow panic-shortcut -- measured backing must include independent spare capacity.
#[test]
#[expect(
    clippy::unwrap_used,
    reason = "actual partial metadata capacities are the test observations"
)]
fn partial_publication_observer_counts_raw_inventory_and_schema_spare_capacity() {
    let mut publication = NativeFreshReportPublication::new();
    publication.raw = Vec::with_capacity(16 * 1024);
    publication.inventory_raw = Vec::with_capacity(8191);
    publication.raw.extend_from_slice(b"partial report");
    publication
        .inventory_raw
        .extend_from_slice(b"partial inventory");
    let mut schema = String::with_capacity(333);
    schema.push_str(PACKET_FRESH_RESTORE_ALLOCATION_REPORT);
    let schema_capacity = schema.capacity();
    publication.schema = Some(schema);
    let mut observer = crate::retained_metadata::MetadataObserver::new();

    publication
        .observe_retained_metadata(&mut observer)
        .unwrap();

    let actual = observer.finish();
    assert_eq!(
        actual.vector_capacity_bytes,
        publication.raw.capacity() + publication.inventory_raw.capacity()
    );
    assert_eq!(actual.string_capacity_bytes, schema_capacity);
    assert!(actual.observed_nodes < 64);
    assert!(publication.report.is_none());
    assert!(publication.completed_response.is_none());
}
