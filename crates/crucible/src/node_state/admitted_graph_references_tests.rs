//! Checks typed admitted graph projection without native or capture authority.

use super::*;
use crate::node_admission::test_fixture_with_content;

#[test]
fn typed_admitted_projection_matches_closed_private_reference_walk() -> Result<(), StateError> {
    let (graph, _) = test_fixture_with_content();
    let rows = admitted_graph_records(&graph, StateLimits::default())?;
    let mut index = 0;
    walk(&graph, |record| {
        let row = &rows[index];
        let mut expected = super::super::closure::core_references(&record, usize::MAX)?;
        expected.sort();
        expected.dedup();
        assert_eq!(row.dependencies(), expected);
        assert_eq!(row.object().bytes, record.canonical_body()?);
        index += 1;
        Ok(())
    })?;
    assert_eq!(index, rows.len());
    Ok(())
}

#[test]
fn graph_projection_refuses_aggregate_edges_and_bytes_before_returning_rows() {
    let (graph, _) = test_fixture_with_content();
    for limits in [
        StateLimits {
            maximum_dependency_edges: 0,
            ..StateLimits::default()
        },
        StateLimits {
            maximum_total_content_bytes: 1,
            ..StateLimits::default()
        },
        StateLimits {
            maximum_content_objects: 1,
            ..StateLimits::default()
        },
    ] {
        assert!(matches!(
            admitted_graph_records(&graph, limits),
            Err(StateError {
                code: StateErrorCode::ResourceLimit,
                ..
            })
        ));
    }
}

#[test]
fn graph_projection_refuses_unknown_nested_extensions() -> Result<(), StateError> {
    let (graph, _) = test_fixture_with_content();
    let mut descriptor = graph
        .descriptor(
            graph
                .node_ids()
                .next()
                .ok_or_else(|| missing("fixture node"))?,
        )
        .ok_or_else(|| missing("fixture descriptor"))?
        .clone();
    descriptor.ports[0].lanes[0]
        .payload_schema
        .extensions
        .insert(
            "unknown.codec".into(),
            serde_json::json!({"hash":"untrusted"}),
        );
    assert!(matches!(
        Record::Descriptor(&descriptor).references(&mut |_| Ok(())),
        Err(StateError {
            code: StateErrorCode::Schema,
            ..
        })
    ));
    Ok(())
}
