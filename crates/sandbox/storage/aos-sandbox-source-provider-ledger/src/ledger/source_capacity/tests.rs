//! UNRUN checked retention/canonical refusal vectors; no runtime qualification.

use super::*;

#[test]
fn duplicated_current_graph_budget_is_checked_before_derivation() {
    let records = BTreeMap::from([(vec![1; 40], vec![2; 1024])]);
    let graph_bytes = 1064;
    let boundary = crate::limits::MAXIMUM_LEDGER_GRAPH_BYTES / graph_bytes;

    assert!(bound_retained_graphs(&records, boundary).is_ok());
    assert!(bound_retained_graphs(&records, boundary + 1).is_err());
    assert!(bound_retained_graphs(&records, usize::MAX).is_err());
    assert!(bound_retained_graphs(&records, 0).is_ok());
}

#[test]
fn duplicate_or_noncanonical_current_rows_refuse_before_owner_selection() {
    let key = vec![1; 40];
    let value = vec![2; 64];
    assert!(derive_source_capacity_owner_data_v1(
        [(key.as_slice(), value.as_slice()), (key.as_slice(), value.as_slice())], &[],
    ).is_err());
    assert!(derive_source_capacity_owner_data_v1(
        [(key.as_slice(), value.as_slice())], &[],
    ).is_err());
}
