//! Checks original diagnostic allocation identity through borrowed rearm views.

use super::*;
use crate::vm_lifecycle::{ProductionVmHotForkSourceRetirementHistory, SourceRetirementCause};

#[test]
fn rearm_view_borrows_original_cause_and_rollback_allocations() {
    let node = NodeId {
        name: String::from("component-node"),
    };
    let first_message = String::from("component rearm capture refusal");
    let first_allocation = first_message.as_ptr();
    let message = String::from("retained rearm diagnostic");
    let message_allocation = message.as_ptr();
    let nodes = vec![node.clone()];
    let node_allocation = nodes.as_ptr();
    let rollback = String::from("retained rollback diagnostic");
    let rollback_allocation = rollback.as_ptr();
    let rearm = SourceRearmHistory {
        first: Some(ProductionVmHotForkSourcePreparationError::Scheduler {
            operation: "component source capture",
            source: SchedulerError::BoundaryViolation {
                message: first_message,
            },
        }),
        message,
        unreconciled_nodes: nodes,
        rollback_diagnostics: BTreeMap::from([(node.clone(), rollback)]),
    };
    let mut history = ProductionVmHotForkSourceRetirementHistory::default();
    history.rearm = Some(rearm);

    let Some(SourceRetirementCause::Rearm(view)) = history.first_failure() else {
        panic!("the actual rearm diagnostic remains a concrete phase");
    };

    assert!(std::ptr::eq(view, history.rearm.as_ref().unwrap()));
    let Some(ProductionVmHotForkSourcePreparationError::Scheduler {
        source: SchedulerError::BoundaryViolation { message },
        ..
    }) = view.first_error()
    else {
        panic!("the scheduler cause remains typed");
    };
    assert_eq!(message.as_ptr(), first_allocation);
    assert_eq!(view.message().as_ptr(), message_allocation);
    assert_eq!(view.unreconciled_nodes().as_ptr(), node_allocation);
    assert_eq!(
        view.rollback_diagnostics()[&node].as_ptr(),
        rollback_allocation
    );
    assert!(!view.is_empty());
    assert!(!history.is_empty());
    assert!(
        history
            .to_string()
            .contains("component rearm capture refusal")
    );
    assert!(history.to_string().contains("retained rollback diagnostic"));
}

#[test]
fn empty_rearm_metadata_does_not_select_an_error_phase() {
    let mut history = ProductionVmHotForkSourceRetirementHistory::default();
    history.rearm = Some(SourceRearmHistory {
        first: None,
        message: String::new(),
        unreconciled_nodes: Vec::new(),
        rollback_diagnostics: BTreeMap::new(),
    });
    let mut visited = 0;

    history
        .visit_history(|_, _| {
            visited += 1;
            Ok(())
        })
        .unwrap();

    assert!(history.is_empty());
    assert!(history.first_failure().is_none());
    assert_eq!(visited, 0);
    assert_eq!(history.to_string(), "Source retirement");
}
