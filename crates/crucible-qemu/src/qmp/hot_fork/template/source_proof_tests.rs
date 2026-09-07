//! Checks strict source provenance and its retained-template proof obligation.

use serde_json::{Value, json};

use super::{native_worker_tests::prepared_report, parse_hot_fork_template_state};
use crate::qmp::hot_fork::block_barrier::parse_hot_fork_block_barrier_state;

#[test]
fn frozen_sources_preserve_original_permissions_and_parentless_roots() -> Result<(), crate::QmpError>
{
    let report = prepared_report();
    let state = parse_hot_fork_template_state(&report)?;
    let block = state.block_barrier();
    let sources = block.snapshot_sources();
    assert!(state.ready());
    assert!(sources.frozen());
    assert_eq!(sources.root_count(), 3);
    assert_eq!(sources.node_count(), 6);
    assert_eq!(sources.originally_writable_root_count(), 2);
    assert_eq!(sources.originally_writable_backend_count(), 1);
    assert_eq!(block.writable_backends(), 0);
    assert_eq!(block.writable_rooted_backends(), 0);
    assert_eq!(block.snapshot_roots().len(), 1);
    Ok(())
}

#[test]
fn malformed_source_provenance_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    for (field, value) in [
        ("schema-version", json!(0)),
        ("schema-version", json!(2)),
        ("frozen", json!(false)),
        ("frozen", json!(1)),
        ("root-count", json!(0)),
        ("root-count", json!(1)),
        ("root-count", json!(7)),
        ("node-count", json!(0)),
        ("node-count", json!(65_537)),
        ("node-count", json!(-1)),
        ("originally-writable-root-count", json!(4)),
        ("originally-writable-backend-count", json!(3)),
        ("originally-writable-backend-count", json!(0)),
        ("unexpected", json!(true)),
    ] {
        let mut report = prepared_report();
        report["block-barrier"]["snapshot-sources"][field] = value;
        assert!(
            parse_hot_fork_template_state(&report).is_err(),
            "{field}: {report}"
        );
    }
    let baseline = prepared_report();
    let fields: Vec<_> = baseline["block-barrier"]["snapshot-sources"]
        .as_object()
        .ok_or("source proof fixture is not an object")?
        .keys()
        .cloned()
        .collect();
    for field in fields {
        let mut report = baseline.clone();
        report["block-barrier"]["snapshot-sources"]
            .as_object_mut()
            .ok_or("source proof fixture is not an object")?
            .remove(&field);
        assert!(
            parse_hot_fork_template_state(&report).is_err(),
            "missing {field}"
        );
    }
    Ok(())
}

#[test]
fn frozen_snapshot_proof_requires_no_current_writable_backend() {
    let mut report = prepared_report();
    report["block-barrier"]["writable-backends"] = json!(1);
    report["block-barrier"]["writable-rooted-backends"] = json!(1);
    assert!(parse_hot_fork_template_state(&report).is_err());
}

#[test]
fn ordinary_snapshot_binding_does_not_acknowledge_frozen_source_proof()
-> Result<(), crate::QmpError> {
    let mut report = prepared_report();
    report["block-barrier"]["snapshot-sources"] = absent_proof();
    report["block-barrier"]["writable-backends"] = json!(1);
    report["block-barrier"]["writable-rooted-backends"] = json!(1);
    let block = parse_hot_fork_block_barrier_state(&report["block-barrier"])?;
    assert!(block.snapshot_complete());
    assert!(!block.snapshot_sources().frozen());
    assert!(parse_hot_fork_template_state(&report).is_err());
    Ok(())
}

#[test]
fn empty_frozen_source_set_is_distinct_from_absent_provenance() -> Result<(), crate::QmpError> {
    let mut report = prepared_report();
    let block = &mut report["block-barrier"];
    block["snapshot-roots"] = json!([]);
    block["snapshot-sources"] = absent_proof();
    block["snapshot-sources"]["frozen"] = json!(true);
    for field in [
        "backend-count",
        "rooted-backends",
        "quiesced-rooted-backends",
    ] {
        block[field] = json!(0);
    }
    assert!(parse_hot_fork_template_state(&report)?.ready());
    report["block-barrier"]["snapshot-sources"]["frozen"] = json!(false);
    assert!(parse_hot_fork_template_state(&report).is_err());
    Ok(())
}

#[test]
fn frozen_source_proof_cannot_survive_snapshot_release_or_missing_wire_field()
-> Result<(), Box<dyn std::error::Error>> {
    let mut report = prepared_report();
    let block = &mut report["block-barrier"];
    block["snapshot-bound"] = json!(false);
    block["snapshot-complete"] = json!(false);
    block["snapshot-roots"] = json!([]);
    for field in [
        "snapshot-owner-thread-id",
        "snapshot-backend-generation",
        "snapshot-graph-mutation-generation",
    ] {
        block[field] = json!(0);
    }
    assert!(parse_hot_fork_block_barrier_state(block).is_err());
    block["snapshot-sources"] = absent_proof();
    assert!(parse_hot_fork_block_barrier_state(block).is_ok());
    block
        .as_object_mut()
        .ok_or("block fixture is not an object")?
        .remove("snapshot-sources");
    assert!(parse_hot_fork_block_barrier_state(block).is_err());
    Ok(())
}

fn absent_proof() -> Value {
    json!({
        "schema-version": 1,
        "frozen": false,
        "root-count": 0,
        "node-count": 0,
        "originally-writable-root-count": 0,
        "originally-writable-backend-count": 0
    })
}
