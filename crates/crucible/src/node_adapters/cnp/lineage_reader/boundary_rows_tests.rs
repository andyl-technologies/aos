//! Synthetic selected-row geometry; these tests confer no native authority.

// crucible-lint: allow panic-shortcut -- finite synthetic codec fixtures localize invalid setup.
#![allow(clippy::unwrap_used)]

use super::{install_selected_rows, selected_row_credit, validate_selected_body};
use crate::node_scheduling::InputPayload;
use crucible_node_contract::{ContentRef, canonical};
use crucible_node_provider::reference_lineage::InputLineageRow;
use std::collections::BTreeMap;

fn object(bytes: &[u8], media: &str) -> InputPayload {
    // crucible-lint: allow panic-shortcut -- these finite bytes and media are valid fixture setup.
    let reference = canonical::content_ref(bytes, media).unwrap();
    InputPayload {
        reference,
        bytes: bytes.to_vec(),
    }
}

fn row(object: &ContentRef, dependencies: &[ContentRef]) -> InputLineageRow {
    InputLineageRow {
        object: object.clone(),
        dependencies: dependencies.to_vec(),
    }
}

#[test]
fn selected_missing_row_is_credited_without_inventing_an_inherited_leaf() {
    let body = object(b"original inherited body", "application/octet-stream");
    let child = object(b"original dependency", "application/octet-stream");
    let mut retained = BTreeMap::new();
    let selected = [row(&body.reference, &[child.reference])];

    assert_eq!(selected_row_credit(&retained, &selected).ok(), Some(1));
    assert!(!retained.contains_key(&body.reference));
    assert!(validate_selected_body(&body, &body.bytes, Some(&body)).is_ok());
    assert!(install_selected_rows(&mut retained, &selected).is_ok());
    assert_eq!(
        retained.get(&body.reference),
        Some(&selected[0].dependencies)
    );
    assert!(install_selected_rows(&mut retained, &selected).is_ok());
    assert_eq!(retained.len(), 1);
}

#[test]
fn authenticated_conflict_refuses_and_identical_row_costs_no_new_credit() {
    let body = object(b"original body", "application/octet-stream");
    let child = object(b"original child", "application/octet-stream");
    let mut retained = BTreeMap::from([(body.reference.clone(), vec![child.reference.clone()])]);

    assert!(selected_row_credit(&retained, &[row(&body.reference, &[])]).is_err());
    assert_eq!(
        selected_row_credit(&retained, &[row(&body.reference, &[child.reference])]).ok(),
        Some(1)
    );
    assert!(install_selected_rows(&mut retained, &[row(&body.reference, &[])]).is_err());
    assert_eq!(retained.len(), 1);
}

#[test]
fn new_selected_rows_cannot_exceed_aggregate_edge_credit() {
    let body = object(b"retained body", "application/octet-stream");
    let child = object(b"dependency", "application/octet-stream");
    let new = object(b"new inherited body", "application/octet-stream");
    let mut retained = BTreeMap::from([(body.reference, vec![child.reference.clone(); 65_536])]);

    assert!(
        selected_row_credit(
            &retained,
            &[row(&new.reference, std::slice::from_ref(&child.reference))]
        )
        .is_err()
    );
    assert!(
        install_selected_rows(&mut retained, &[row(&new.reference, &[child.reference])]).is_err()
    );
    assert!(!retained.contains_key(&new.reference));
    assert_eq!(retained.values().map(Vec::len).sum::<usize>(), 65_536);
}

#[test]
fn exact_source_body_and_full_typed_role_are_preserved() {
    let body = object(b"original body", "application/octet-stream");
    let other_role = object(b"original body", "application/vnd.test.original");
    let altered = object(b"changed body", "application/octet-stream");

    assert!(validate_selected_body(&body, b"changed body", Some(&body)).is_err());
    assert!(validate_selected_body(&body, &body.bytes, Some(&altered)).is_err());
    assert!(validate_selected_body(&body, &body.bytes, Some(&other_role)).is_err());
    assert!(validate_selected_body(&body, &body.bytes, Some(&body)).is_ok());
    assert!(validate_selected_body(&other_role, &other_role.bytes, Some(&other_role)).is_ok());
    assert_eq!(body.reference.hash, other_role.reference.hash);
    assert_ne!(body.reference, other_role.reference);
}
