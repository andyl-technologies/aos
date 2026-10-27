//! Genuine absent-custody refusal with the same real canceled Original.
//!
//! No authenticated node, subdivision, Main, Source or native grant is created.

use super::*;
use crate::host_supervision::{HostOperationBudgets, HostOperationClass, HostOperationSupervisor};

#[test]
fn absent_raw_source_preserves_both_slots_and_the_independent_original_refusal() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let operation = original.status().unwrap().operation_id;
    supervisor.cancel().unwrap();
    let refused = original.wait_slice().unwrap_err();
    let mut source = None;
    let mut destination = None;

    let report =
        AuthenticatedNativeNodeClaim::move_to_subdivision(&mut source, &mut destination, &original)
            .unwrap_err();

    assert!(source.is_none());
    assert!(destination.is_none());
    assert!(matches!(&report.cause, ServiceBirthError::Policy(message)
        if message == "native node custody is absent"));
    assert!(
        matches!(report.after.as_ref(), Some(ServiceBirthError::Supervision(actual)) if *actual == refused)
    );
    assert!(report._retained.is_empty());
    assert!(!report.world_assignment_was_refused());
    assert_eq!(original.status().unwrap().operation_id, operation);
}

#[test]
fn running_preparation_without_an_actual_node_cannot_create_a_subdivision() {
    let supervisor = HostOperationSupervisor::new(HostOperationBudgets::default(), None).unwrap();
    let original = Arc::new(supervisor.begin(HostOperationClass::Preparation).unwrap());
    let before = original.status().unwrap();
    let mut source = None;
    let mut destination = None;

    let report =
        AuthenticatedNativeNodeClaim::move_to_subdivision(&mut source, &mut destination, &original)
            .unwrap_err();

    assert!(source.is_none());
    assert!(destination.is_none());
    assert!(matches!(&report.cause, ServiceBirthError::Policy(message)
        if message == "native node custody is absent"));
    assert!(report.after.is_none());
    assert!(report._retained.is_empty());
    assert!(!report.world_assignment_was_refused());
    let after = original.status().unwrap();
    assert_eq!(after.operation_id, before.operation_id);
    assert_eq!(after.state, before.state);
}
